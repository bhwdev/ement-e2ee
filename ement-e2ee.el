;;; ement-e2ee.el --- End-to-end encryption for ement.el via a local proxy  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ben H. W.

;; Author: Ben H. W. <foss@bhw.name>
;; Maintainer: Ben H. W. <foss@bhw.name>
;; URL: https://github.com/bhwdev/ement-e2ee
;; Version: 0.19.1
;; Package-Requires: ((emacs "28.1") (ement "0.16") (plz "0.7"))
;; Keywords: comm
;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; ement-e2ee is a local proxy, written in Rust on matrix-sdk-crypto,
;; that gives ement.el end-to-end encryption without changing ement:
;; it decrypts what ement receives and encrypts what ement sends.
;; This package runs the proxy and routes ement through it.
;;
;; Once, after installing the package:
;;
;;   M-x ement-e2ee-install
;;
;; gets the proxy binary (a prebuilt one, checked against the release's
;; SHA256SUMS, or one built with cargo), writes its config for your
;; account, and turns on `ement-e2ee-mode'.  From then on M-x
;; ement-connect works as before: the mode starts the proxy when ement
;; first needs it, keeps it running, and stops it when the last session
;; disconnects.
;;
;; Then join your encrypted identity with M-x ement-e2ee-bootstrap
;; (asks for the recovery key) and, optionally, verify the device with
;; M-x ement-e2ee-verify.  M-x ement-e2ee-check tells what, if
;; anything, is wrong; M-x ement-e2ee-log shows the proxy's log.

;;; Code:

(require 'cl-lib)
(require 'json)
(require 'plz)
(require 'subr-x)

;; Everything below that touches ement runs from ement's own commands
;; and hooks, so ement is loaded by then.  Its structs are accessed
;; through functions, not inlined: their layout is ement's business.
(defvar ement-sessions)
(defvar ement-syncs)
(defvar ement-connect-user-id-history)
(declare-function ement-session-user "ement-structs" (session))
(declare-function ement-session-server "ement-structs" (session))
(declare-function ement-user-id "ement-structs" (user))
(declare-function ement-server-uri-prefix "ement-structs" (server))
(declare-function ement-room-sync "ement-room" (session &optional force))
(declare-function compilation-start "compile"
                  (command &optional mode name-function highlight-regexp continue))

;;;; Customization

(defgroup ement-e2ee nil
  "End-to-end encryption for ement.el, through the ement-e2ee proxy."
  :group 'ement
  :link '(url-link "https://github.com/bhwdev/ement-e2ee")
  :prefix "ement-e2ee-")

(defconst ement-e2ee-binary-version "0.19.1"
  "The version of the ement-e2ee proxy this package is made for.
A binary at least this new is accepted; `ement-e2ee-install' gets
exactly this one.")

(defcustom ement-e2ee-program nil
  "The ement-e2ee executable to run, or nil to find one.
When nil, the \"ement-e2ee\" in the directories of variable
`exec-path' is used if it is at least version
`ement-e2ee-binary-version', else the one
`ement-e2ee-install' keeps under `ement-e2ee-binary-directory'.
A program set here has to be new enough as well."
  :type '(choice (const :tag "Find it" nil) file))

(defcustom ement-e2ee-binary-directory (locate-user-emacs-file "ement-e2ee/")
  "Where `ement-e2ee-install' puts the binaries it downloads or builds.
Each version gets a directory of its own: VERSION/bin/ement-e2ee.
Those of older versions are deleted once a proxy of the version
this package needs has started."
  :type 'directory)

(defcustom ement-e2ee-config-file nil
  "The proxy's config file, or nil for its default.
The default is config.toml in the ement-e2ee directory under the
user's config directory (usually ~/.config/ement-e2ee/).  Every
run of the binary is given this file."
  :type '(choice (const :tag "The binary's default" nil) file))

(defcustom ement-e2ee-auto-install 'ask
  "What `ement-connect' does when the proxy binary is missing.
`ask': offer to download or build it, like `ement-e2ee-install'.
t: download it without asking, or build it where no prebuilt
binary exists.
nil: signal an error that points to `ement-e2ee-install'."
  :type '(choice (const :tag "Ask" ask)
                 (const :tag "Install without asking" t)
                 (const :tag "Signal an error" nil)))

(defcustom ement-e2ee-accounts t
  "Which accounts `ement-connect' routes through the proxy.
t means all of them; otherwise a list of Matrix user IDs, like
\(\"@you:example.org\").  The proxy serves the one homeserver its
config names, so route only accounts on that server."
  :type '(choice (const :tag "All accounts" t)
                 (repeat :tag "These user IDs" string)))

(defcustom ement-e2ee-stop-on-disconnect t
  "Whether to stop the proxy when the last session using it disconnects.
Only a proxy this Emacs started is stopped."
  :type 'boolean)

(defcustom ement-e2ee-startup-timeout 30
  "Seconds to wait for the proxy to start answering.
Start-up includes the config's store_passphrase_command, which
may wait for a passphrase prompt, so leave time for that."
  :type 'number)

(defcustom ement-e2ee-log-max-lines 5000
  "How many lines of the proxy's output its log buffer keeps."
  :type 'natnum)

(defcustom ement-e2ee-serve-arguments nil
  "Further arguments to \"ement-e2ee serve\", like (\"--log-level\" \"debug\")."
  :type '(repeat string))

(defcustom ement-e2ee-release-url
  "https://github.com/bhwdev/ement-e2ee/releases/download/v%s/"
  "Where `ement-e2ee-install' downloads prebuilt binaries from.
A format string for the version.  The files ement-e2ee-TARGET
and SHA256SUMS are fetched from under it."
  :type 'string)

;;;; Variables

(defconst ement-e2ee--repository "https://github.com/bhwdev/ement-e2ee"
  "The source repository, for building with cargo.")

(defconst ement-e2ee--prebuilt-targets
  '("x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl" "aarch64-apple-darwin")
  "The targets each release has a prebuilt binary for.")

(defconst ement-e2ee--log-buffer-name "*ement-e2ee*"
  "The buffer holding the output of the proxy this Emacs runs.")

(defvar ement-e2ee--process nil
  "The proxy process this Emacs started, if any.")

(defvar ement-e2ee--adopted nil
  "A proxy found running when this Emacs needed one.
The alist its version route answered: name, version, pid.")

(defvar ement-e2ee--url nil
  "The proxy's base URL, as last read from its config.")

(defvar ement-e2ee--stopping nil
  "Non-nil while the proxy this Emacs started is being stopped on purpose.")

(defvar ement-e2ee--backoff 0
  "The exponent of the delay before the next supervised restart.")

(defvar ement-e2ee--quick-deaths 0
  "How many times in a row the proxy exited soon after it started.")

(defvar ement-e2ee--restart-timer nil
  "The timer of a pending supervised restart.")

(defvar ement-e2ee--ready-timer nil
  "The timer polling a proxy started in the background until it answers.")

(defvar ement-e2ee--watchdog-timer nil
  "The timer checking that an adopted proxy is still there.")

(defvar ement-e2ee--hinted nil
  "User IDs that have had the bootstrap hint.")

(defvar ement-e2ee--backoff-unit 1.0
  "Seconds the delay before a supervised restart doubles from.")

(defconst ement-e2ee--quick-death-seconds 5
  "An exit this soon after the start counts as failing to start.")

(defconst ement-e2ee--max-quick-deaths 4
  "Failures to start in a row after which supervision gives up.")

(defconst ement-e2ee--stable-seconds 60
  "Uptime after which the restart delay starts again from the bottom.")

(defconst ement-e2ee--max-backoff 60
  "The longest delay before a supervised restart, in backoff units.")

(defconst ement-e2ee--watchdog-interval 60
  "Seconds between checks on an adopted proxy.")

;;;; Resolution

(defun ement-e2ee--version-list (version)
  "Return the semantic VERSION as a list for `version-list-<', or nil.
A pre-release (as in 0.19.0-rc.1) comes before its release; build
metadata (+...) is ignored."
  (when (and (stringp version)
             (string-match (rx bos (group (+ digit) (* "." (+ digit)))
                               (? (group "-" (+ (not (in "+")))))
                               (? "+" (* anything)) eos)
                           version))
    (append (version-to-list (match-string 1 version))
            (and (match-beginning 2) '(-1)))))

(defun ement-e2ee--version< (a b)
  "Whether the semantic version A is older than B; nil if either is none."
  (let ((a (ement-e2ee--version-list a))
        (b (ement-e2ee--version-list b)))
    (and a b (version-list-< a b))))

(defun ement-e2ee--parse-version (output)
  "Return the version in OUTPUT of \"ement-e2ee --version\", or nil."
  (when (string-match (rx bos (* (in " \t\n")) "ement-e2ee" (+ (in " \t"))
                          (group (+ (not (in " \t\n"))))
                          (* (in " \t\n")) eos)
                      output)
    (let ((version (match-string 1 output)))
      (and (ement-e2ee--version-list version) version))))

(defun ement-e2ee--new-enough-p (version)
  "Whether VERSION is at least `ement-e2ee-binary-version'."
  (and (ement-e2ee--version-list version)
       (not (ement-e2ee--version< version ement-e2ee-binary-version))))

(defun ement-e2ee--binary-version (program)
  "Return the version PROGRAM reports, or nil if it reports none."
  (with-temp-buffer
    (when (eq 0 (ignore-errors (call-process program nil t nil "--version")))
      (ement-e2ee--parse-version (buffer-string)))))

(defun ement-e2ee--managed-binary (&optional version)
  "Return the path of the binary of VERSION that `ement-e2ee-install' gets.
VERSION defaults to `ement-e2ee-binary-version'."
  (expand-file-name (concat (or version ement-e2ee-binary-version) "/bin/ement-e2ee")
                    ement-e2ee-binary-directory))

(defun ement-e2ee--managed-directory-p (directory)
  "Whether DIRECTORY has nothing but what `ement-e2ee-install' puts there.
That is bin/ement-e2ee (or a partial download of it) and the
records of cargo install."
  (let ((bin (expand-file-name "bin" directory)))
    (and (file-directory-p directory)
         (not (file-symlink-p directory))
         (cl-subsetp (directory-files directory nil directory-files-no-dot-files-regexp)
                     '("bin" ".crates.toml" ".crates2.json")
                     :test #'equal)
         (or (not (file-exists-p bin))
             (and (file-directory-p bin)
                  (not (file-symlink-p bin))
                  (cl-subsetp (directory-files bin nil directory-files-no-dot-files-regexp)
                              '("ement-e2ee" "ement-e2ee.part")
                              :test #'equal))))))

(defun ement-e2ee--old-binary-directories ()
  "Return the directories `ement-e2ee-install' made for older versions."
  (and (file-directory-p ement-e2ee-binary-directory)
       (cl-loop for directory in (directory-files ement-e2ee-binary-directory t (rx bos digit))
                for version = (file-name-nondirectory directory)
                when (and (ement-e2ee--version< version ement-e2ee-binary-version)
                          (ement-e2ee--managed-directory-p directory))
                collect directory)))

(defun ement-e2ee--locate-binary ()
  "Return the ement-e2ee executable to run, or nil if there is none.
Signal an error if `ement-e2ee-program' is set but not usable."
  (if ement-e2ee-program
      (let* ((program (or (executable-find ement-e2ee-program)
                          (expand-file-name ement-e2ee-program)))
             (version (ement-e2ee--binary-version program)))
        (unless (ement-e2ee--new-enough-p version)
          (user-error "Ement-e2ee: `ement-e2ee-program' %s is %s; this needs version %s or newer"
                      program
                      (if version (concat "version " version) "no working ement-e2ee")
                      ement-e2ee-binary-version))
        program)
    (or (when-let ((found (executable-find "ement-e2ee")))
          (and (ement-e2ee--new-enough-p (ement-e2ee--binary-version found))
               found))
        (let ((managed (ement-e2ee--managed-binary)))
          (and (file-executable-p managed) managed)))))

(defun ement-e2ee--program ()
  "Return the ement-e2ee executable to run, or signal that there is none."
  (or (ement-e2ee--locate-binary)
      (user-error "Ement-e2ee: no ement-e2ee %s or newer; M-x ement-e2ee-install gets one"
                  ement-e2ee-binary-version)))

(defun ement-e2ee--target ()
  "Return this system's release target, or nil if none is built for it."
  (let* ((cpu (pcase (car (split-string system-configuration "-"))
                ((or "x86_64" "amd64") "x86_64")
                ((or "aarch64" "arm64") "aarch64")))
         (os (pcase system-type
               ('gnu/linux "unknown-linux-musl")
               ('darwin "apple-darwin")))
         (target (and cpu os (concat cpu "-" os))))
    (car (member target ement-e2ee--prebuilt-targets))))

;;;; Running the binary

(defun ement-e2ee--config-args ()
  "Return the arguments that pass `ement-e2ee-config-file' on."
  (and ement-e2ee-config-file
       (list "--config" (expand-file-name ement-e2ee-config-file))))

(defun ement-e2ee--call (program &rest args)
  "Run PROGRAM with ARGS and nothing on its standard input.
Return its exit status and output as (STATUS . OUTPUT)."
  (with-temp-buffer
    (let ((status (apply #'call-process program nil t nil args)))
      (cons status (buffer-string)))))

(defun ement-e2ee--json (string)
  "Parse the JSON STRING into alists, or return nil if it is not JSON."
  (let ((json-object-type 'alist)
        (json-array-type 'list)
        (json-key-type 'symbol)
        (json-null nil)
        (json-false nil))
    (ignore-errors (json-read-from-string string))))

(defun ement-e2ee--info (&optional program)
  "Return PROGRAM's \"info --json\" report on the config, as an alist.
PROGRAM defaults to the located binary.  This reads the config
only; it runs no store_passphrase_command."
  (pcase-let ((`(,status . ,output)
               (apply #'ement-e2ee--call (or program (ement-e2ee--program))
                      "info" "--json" (ement-e2ee--config-args))))
    (or (and (eq status 0) (ement-e2ee--json output))
        (error "Ement-e2ee info failed: %s" (string-trim output)))))

;;;; Installation

(defun ement-e2ee--fetch (url &optional file)
  "Fetch URL with curl into FILE, or return its contents as a string."
  (with-temp-buffer
    (let ((status (apply #'call-process plz-curl-program nil t nil
                         "--fail" "--location" "--silent" "--show-error"
                         (append (and file (list "--output" file)) (list url)))))
      (unless (eq status 0)
        (error "Could not fetch %s: %s" url (string-trim (buffer-string))))
      (unless file
        (buffer-string)))))

(defun ement-e2ee--expected-sha256 (sums asset)
  "Return the SHA-256 that SUMS, the text of a SHA256SUMS file, gives ASSET."
  (or (cl-loop for line in (split-string sums "\n" t)
               when (and (string-match (rx bos (group (= 64 hex)) (+ blank) (? "*")
                                           (group (+ nonl)) eos)
                                       line)
                         (equal (match-string 2 line) asset))
               return (downcase (match-string 1 line)))
      (error "SHA256SUMS lists no %s" asset)))

(defun ement-e2ee--verify-sha256 (file expected)
  "Signal an error unless FILE's SHA-256 is EXPECTED."
  (let ((actual (with-temp-buffer
                  (set-buffer-multibyte nil)
                  (insert-file-contents-literally file)
                  (secure-hash 'sha256 (current-buffer)))))
    (unless (string= actual expected)
      (error "Checksum mismatch for %s: expected %s, got %s"
             (file-name-nondirectory file) expected actual))))

(defun ement-e2ee--fetch-sums (base version)
  "Fetch the SHA256SUMS of the release of VERSION, under BASE.
Say plainly when there is no such release (yet)."
  (condition-case err
      (ement-e2ee--fetch (concat base "SHA256SUMS"))
    (error
     (if (string-match-p (rx "returned error: 404") (error-message-string err))
         (user-error "Ement-e2ee: ement-e2ee %s has no release at %s yet; its binaries \
may still be building: try again in a few minutes, or build it with M-x ement-e2ee-install"
                     version base)
       (signal (car err) (cdr err))))))

(defun ement-e2ee--download (target version)
  "Download the release binary of VERSION for TARGET; return its path.
It goes where `ement-e2ee--managed-binary' says, and only once
its checksum matches the release's SHA256SUMS."
  (let* ((base (format ement-e2ee-release-url version))
         (asset (concat "ement-e2ee-" target))
         (binary (ement-e2ee--managed-binary version))
         (part (concat binary ".part"))
         (done nil))
    (unwind-protect
        (let ((expected (ement-e2ee--expected-sha256
                         (ement-e2ee--fetch-sums base version) asset)))
          (make-directory (file-name-directory binary) t)
          (message "Ement-e2ee: downloading %s..." asset)
          (when (file-exists-p part)
            (delete-file part))
          (ement-e2ee--fetch (concat base asset) part)
          (ement-e2ee--verify-sha256 part expected)
          (set-file-modes part #o755)
          (rename-file part binary t)
          (unless (equal (ement-e2ee--binary-version binary) version)
            (delete-file binary)
            (error "The downloaded ement-e2ee does not run as version %s" version))
          (setq done t)
          (message "Ement-e2ee: installed %s" binary)
          binary)
      (unless done
        (when (file-exists-p part)
          (delete-file part))))))

(defun ement-e2ee--cargo ()
  "Return the cargo executable, or nil if there is none."
  (or (executable-find "cargo")
      (let ((cargo (expand-file-name "~/.cargo/bin/cargo")))
        (and (file-executable-p cargo) cargo))))

(defun ement-e2ee--manifest-version (manifest)
  "Return the package version in the Cargo.toml MANIFEST."
  (with-temp-buffer
    (insert-file-contents manifest)
    (when (re-search-forward (rx bol "version" (* blank) "=" (* blank) "\""
                                 (group (+ (not (in "\"")))) "\"")
                             nil t)
      (match-string 1))))

(defun ement-e2ee--checkout ()
  "Return this package's source tree, if it has the Rust code of this version.
Packages installed from Git (package-vc, straight, elpaca) have it."
  (when-let* ((library (locate-library "ement-e2ee.el"))
              (directory (file-name-directory (file-truename library)))
              (manifest (expand-file-name "Cargo.toml" directory)))
    (and (file-readable-p manifest)
         (equal (ement-e2ee--manifest-version manifest) ement-e2ee-binary-version)
         directory)))

(defun ement-e2ee--build-command (cargo)
  "Return the shell command that builds the binary with CARGO."
  (let ((root (expand-file-name ement-e2ee-binary-version ement-e2ee-binary-directory))
        (checkout (ement-e2ee--checkout)))
    (mapconcat #'shell-quote-argument
               `(,cargo "install" "--locked" "--root" ,root
                        ,@(if checkout
                              (list "--path" checkout)
                            (list "--git" ement-e2ee--repository
                                  "--tag" (concat "v" ement-e2ee-binary-version))))
               " ")))

(defun ement-e2ee--build (cargo)
  "Build the binary with CARGO, then continue `ement-e2ee-install'."
  (require 'compile)
  (let ((buffer (compilation-start (ement-e2ee--build-command cargo) nil
                                   (lambda (_mode) "*ement-e2ee build*"))))
    (with-current-buffer buffer
      (add-hook 'compilation-finish-functions #'ement-e2ee--build-finished nil t))
    (message "Ement-e2ee: building; the installation continues once that is done")))

(defun ement-e2ee--build-finished (_buffer outcome)
  "Continue `ement-e2ee-install' if the build's OUTCOME is success."
  (if (string-prefix-p "finished" outcome)
      ;; Out of the process sentinel: the rest may ask questions.
      (run-at-time 0 nil #'ement-e2ee-install)
    (message "Ement-e2ee: the build failed; see the *ement-e2ee build* buffer")))

(defun ement-e2ee--older-version ()
  "Return the newest installed ement-e2ee older than this package needs, or nil.
That is one `ement-e2ee-install' got, or one on variable `exec-path'."
  (let ((versions (cons (when-let ((found (executable-find "ement-e2ee")))
                          (ement-e2ee--binary-version found))
                        (cl-loop for directory in (ement-e2ee--old-binary-directories)
                                 for version = (file-name-nondirectory directory)
                                 when (file-executable-p (ement-e2ee--managed-binary version))
                                 collect version))))
    (car (sort (cl-remove-if-not
                (lambda (version) (ement-e2ee--version< version ement-e2ee-binary-version))
                versions)
               (lambda (a b) (ement-e2ee--version< b a))))))

(defun ement-e2ee--obtain-question ()
  "Return the question `ement-e2ee--obtain-binary' asks."
  (let ((older (ement-e2ee--older-version)))
    (cond ((file-executable-p (ement-e2ee--managed-binary))
           (format "Get ement-e2ee %s again?" ement-e2ee-binary-version))
          (older
           (format "ement-e2ee.el now needs ement-e2ee %s (installed: %s).  Get it?"
                   ement-e2ee-binary-version older))
          (t
           (format "ement-e2ee %s is not installed.  Get it?" ement-e2ee-binary-version)))))

(defun ement-e2ee--obtain-binary (no-ask)
  "Download or build the binary, asking which unless NO-ASK.
Return the binary's path, or `building' while cargo builds it."
  (let* ((target (ement-e2ee--target))
         (cargo (ement-e2ee--cargo))
         (choices (append
                   (and target '((?d "download" "Download the release's prebuilt binary")))
                   (and cargo '((?b "build" "Build it with cargo install --locked")))
                   (and (not no-ask) '((?q "quit" "Do neither"))))))
    (unless (or target cargo)
      (user-error "Ement-e2ee: no prebuilt binary for %s, and no cargo to build one with"
                  system-configuration))
    (pcase (if no-ask
               (car choices)
             (read-multiple-choice (ement-e2ee--obtain-question) choices))
      (`(?d . ,_) (ement-e2ee--download target ement-e2ee-binary-version))
      (`(?b . ,_) (ement-e2ee--build cargo) 'building)
      (_ (user-error "Ement-e2ee: nothing installed")))))

(defun ement-e2ee--delete-superseded-binaries ()
  "Delete the binaries `ement-e2ee-install' got for older versions.
This package runs none of them, and a proxy of the version it
needs, once started, has marked the store as used by that
version: older ones refuse to start there."
  (when-let ((old (ement-e2ee--old-binary-directories)))
    (condition-case err
        (progn
          (dolist (directory old)
            (delete-directory directory t))
          (ement-e2ee--log-note "deleted the binaries of ement-e2ee %s"
                                (mapconcat #'file-name-nondirectory old ", ")))
      (error (ement-e2ee--log-note "could not delete older binaries: %s"
                                   (error-message-string err))))))

;;;; Configuration

(defun ement-e2ee--read-user-id ()
  "Read a Matrix user ID, offering the one ement knows."
  (let ((default (or (car (car (bound-and-true-p ement-sessions)))
                     (car (bound-and-true-p ement-connect-user-id-history)))))
    (read-string (format-prompt "Matrix user ID" default)
                 nil 'ement-connect-user-id-history default)))

(defun ement-e2ee--setup (program user-id force)
  "Run PROGRAM's setup for USER-ID, replacing the config if FORCE."
  (message "Ement-e2ee: setting up for %s..." user-id)
  (pcase-let ((`(,status . ,output)
               (apply #'ement-e2ee--call program "setup" "--user-id" user-id
                      (append (and force '("--force")) (ement-e2ee--config-args)))))
    (unless (eq status 0)
      (with-current-buffer (get-buffer-create "*ement-e2ee setup*")
        (let ((inhibit-read-only t))
          (erase-buffer)
          (insert output))
        (special-mode)
        (display-buffer (current-buffer)))
      (user-error "Ement-e2ee: setup failed: %s"
                  (car (last (split-string (string-trim output) "\n")))))))

(defun ement-e2ee--ensure-config (program &optional user-id)
  "Write PROGRAM's config unless it names a homeserver.
Set it up for USER-ID, or for an account read from the user."
  (unless (alist-get 'homeserver (ement-e2ee--info program))
    (ement-e2ee--setup program (or user-id (ement-e2ee--read-user-id)) nil)))

;;;; Supervision

(defvar-local ement-e2ee--log-lines 0
  "Roughly how many lines the log buffer holds.")

(defun ement-e2ee--log-buffer ()
  "Return the log buffer, making it if need be.
The proxy process has no buffer: killing this one only discards
the log.  And its mode is plain `special-mode', since
`ement-disconnect' kills every buffer whose mode is ement's
\(`ement-kill-buffers'), while the proxy may well outlive a session."
  (or (get-buffer ement-e2ee--log-buffer-name)
      (with-current-buffer (get-buffer-create ement-e2ee--log-buffer-name)
        (special-mode)
        (current-buffer))))

(defun ement-e2ee--log-insert (text)
  "Append TEXT to the log buffer, following it where point was at the end."
  (let ((buffer (ement-e2ee--log-buffer)))
    (with-current-buffer buffer
      (let ((inhibit-read-only t)
            (at-end (= (point) (point-max)))
            (windows (cl-remove-if-not (lambda (window)
                                         (= (window-point window) (point-max)))
                                       (get-buffer-window-list buffer nil t))))
        (save-excursion
          (goto-char (point-max))
          (insert text)
          (cl-incf ement-e2ee--log-lines (cl-count ?\n text))
          ;; Trim in batches, not at every line.
          (when (> ement-e2ee--log-lines (* 1.1 ement-e2ee-log-max-lines))
            (forward-line (- ement-e2ee-log-max-lines))
            (delete-region (point-min) (line-beginning-position))
            (setq ement-e2ee--log-lines ement-e2ee-log-max-lines)))
        (when at-end
          (goto-char (point-max)))
        (dolist (window windows)
          (set-window-point window (point-max)))))))

(defun ement-e2ee--log-note (format-string &rest args)
  "Note in the log buffer what this package did: FORMAT-STRING with ARGS."
  (ement-e2ee--log-insert (format "[ement-e2ee.el %s] %s\n"
                                  (format-time-string "%F %T")
                                  (apply #'format format-string args))))

(defun ement-e2ee--log-tail (&optional lines)
  "Return the last LINES (default 10) lines of the log buffer."
  (if-let ((buffer (get-buffer ement-e2ee--log-buffer-name)))
      (with-current-buffer buffer
        (save-excursion
          (goto-char (point-max))
          (skip-chars-backward "\n")
          (forward-line (- 1 (or lines 10)))
          (string-trim-right
           (buffer-substring-no-properties (line-beginning-position) (point-max)))))
    ""))

(defun ement-e2ee--filter (_process output)
  "Append a proxy process's OUTPUT to the log buffer."
  (ement-e2ee--log-insert output))

(defun ement-e2ee--spawn (program version supervised)
  "Start PROGRAM, of VERSION, as the proxy; return the process.
SUPERVISED means restart it when it dies; otherwise that only
starts once it has answered."
  (let* ((command `(,program "serve" "--exit-on-stdin-close"
                             ,@(ement-e2ee--config-args) ,@ement-e2ee-serve-arguments))
         ;; Standard input is a pipe nobody writes to: when Emacs ends,
         ;; however it ends, the proxy sees end of file and exits.
         (process (make-process :name "ement-e2ee" :buffer nil :command command
                                :connection-type 'pipe :noquery t
                                :coding 'utf-8-unix
                                :filter #'ement-e2ee--filter
                                :sentinel #'ement-e2ee--sentinel)))
    (process-put process 'started (float-time))
    (process-put process 'version version)
    (process-put process 'supervised supervised)
    (setq ement-e2ee--process process
          ement-e2ee--stopping nil
          ement-e2ee--adopted nil)
    (ement-e2ee--cancel-watchdog)
    (ement-e2ee--log-note "started %s (pid %d)"
                          (mapconcat #'shell-quote-argument command " ")
                          (process-id process))
    process))

(defun ement-e2ee--sentinel (process event)
  "Handle PROCESS's EVENT: restart the proxy if it died unexpectedly."
  (unless (process-live-p process)
    (ement-e2ee--log-note "proxy (pid %d) %s" (process-id process) (string-trim event))
    (when (eq process ement-e2ee--process)
      (setq ement-e2ee--process nil)
      (ement-e2ee--cancel-ready-timer)
      (cond (ement-e2ee--stopping
             (setq ement-e2ee--stopping nil)
             (message "Ement-e2ee: the proxy stopped"))
            ((process-get process 'supervised)
             (ement-e2ee--schedule-restart process))))))

(defun ement-e2ee--schedule-restart (process)
  "Restart the proxy after PROCESS died, backing off, or give up."
  (let ((uptime (- (float-time) (process-get process 'started))))
    (if (< uptime ement-e2ee--quick-death-seconds)
        (cl-incf ement-e2ee--quick-deaths)
      (setq ement-e2ee--quick-deaths 0))
    (when (>= uptime ement-e2ee--stable-seconds)
      (setq ement-e2ee--backoff 0))
    (if (>= ement-e2ee--quick-deaths ement-e2ee--max-quick-deaths)
        (ement-e2ee--give-up)
      (let ((delay (* ement-e2ee--backoff-unit
                      (min ement-e2ee--max-backoff (expt 2 ement-e2ee--backoff)))))
        (cl-incf ement-e2ee--backoff)
        (ement-e2ee--log-note "restarting in %s s" delay)
        (setq ement-e2ee--restart-timer
              (run-at-time delay nil #'ement-e2ee--restart-supervised))))))

(defun ement-e2ee--give-up ()
  "Stop restarting the proxy and say why it fails."
  (let* ((tail (ement-e2ee--log-tail 8))
         (newer (and (string-match (rx "install ≥ " (group (+ (in digit ".")))) tail)
                     (match-string 1 tail))))
    (setq ement-e2ee--quick-deaths 0
          ement-e2ee--backoff 0)
    (ement-e2ee--log-note "gave up restarting")
    (display-warning
     'ement-e2ee
     (concat (format "The proxy failed to start %d times in a row; gave up."
                     ement-e2ee--max-quick-deaths)
             (and newer
                  (format "  Its store was last used by ement-e2ee %s: \
update this package, then C-u M-x ement-e2ee-install for version %s or newer."
                          newer newer))
             "  Last lines of its log (M-x ement-e2ee-log):\n\n"
             tail)
     :error)))

(defun ement-e2ee--restart-supervised ()
  "Restart the proxy in the background, unless one is running."
  (setq ement-e2ee--restart-timer nil)
  (unless (process-live-p ement-e2ee--process)
    (condition-case err
        (ement-e2ee--start-async)
      (error
       (ement-e2ee--log-note "could not restart: %s" (error-message-string err))
       (display-warning 'ement-e2ee
                        (format "Could not restart the proxy: %s"
                                (error-message-string err))
                        :error)))))

(defun ement-e2ee--start-async ()
  "Start a supervised proxy; resume ement's syncs once it answers."
  (let* ((program (ement-e2ee--program))
         (info (ement-e2ee--info program))
         (url (alist-get 'url info))
         (process (ement-e2ee--spawn program (alist-get 'version info) t)))
    (setq ement-e2ee--url url)
    (ement-e2ee--when-ready process url #'ement-e2ee--resume-syncs)))

(defun ement-e2ee--probe (url &optional timeout)
  "Ask what listens at URL, waiting at most TIMEOUT seconds (default 2).
Return (proxy . ALIST) for an ement-e2ee proxy, ALIST being its
answer on the version route; `nothing' when nothing answers; or
\(other . DESCRIPTION) for anything else.

Nothing answers when the connection is refused, or when it times
out: with WSL2's mirrored networking, connecting to a loopback
port nobody listens on hangs instead of failing.  Something that
accepts connections and never answers counts as nothing too; a
proxy started on its port then fails, and says why."
  (let ((timeout (or timeout 2)))
    (condition-case err
        (let* ((response (plz 'get (concat url "/_ement/version")
                           :as 'response :then 'sync
                           ;; Loopback: a listener accepts at once.
                           :connect-timeout (min timeout 0.5) :timeout timeout))
               (body (ement-e2ee--json (plz-response-body response))))
          (if (equal (alist-get 'name body) "ement-e2ee")
              (cons 'proxy body)
            (cons 'other (format "it answers HTTP %s" (plz-response-status response)))))
      (plz-error
       (let* ((data (nth 2 err))
              (data (and (plz-error-p data) data))
              (response (and data (plz-error-response data)))
              (body (and response (plz-response-body response))))
         (pcase (and data (plz-error-curl-error data))
           (`(,(or 7 28) . ,_) 'nothing)
           (`(,code . ,message) (cons 'other (format "curl error %s: %s" code message)))
           (_ (cons 'other
                    (if (and body (string-search "unknown admin route" body))
                        "an ement-e2ee older than 0.18 runs there; stop it first"
                      (format "it answers HTTP %s"
                              (and response (plz-response-status response))))))))))))

(defun ement-e2ee--answering-p (process url)
  "Whether PROCESS is the proxy answering at URL."
  (pcase (ement-e2ee--probe url 1)
    (`(proxy . ,body) (eql (alist-get 'pid body) (process-id process)))))

(defun ement-e2ee--mark-ready (process)
  "Note that PROCESS answers, and supervise it from now on.
A proxy of the version this package needs makes the binaries of
older ones useless: delete them."
  (process-put process 'ready t)
  (process-put process 'supervised t)
  (ement-e2ee--log-note "answering on %s" ement-e2ee--url)
  (when (ement-e2ee--new-enough-p (process-get process 'version))
    (ement-e2ee--delete-superseded-binaries)))

(defun ement-e2ee--drain (process)
  "Read what PROCESS has still written."
  (while (accept-process-output process 0.05)))

(defun ement-e2ee--startup-failed (what)
  "Signal that the proxy did not start, WHAT happened and its last words."
  (when-let ((buffer (get-buffer ement-e2ee--log-buffer-name)))
    (display-buffer buffer))
  (user-error "Ement-e2ee: %s:\n%s" what (ement-e2ee--log-tail 5)))

(defun ement-e2ee--wait-ready (process url)
  "Wait until PROCESS answers at URL, for `ement-e2ee-startup-timeout' at most."
  (let ((deadline (+ (float-time) ement-e2ee-startup-timeout)))
    (while (not (ement-e2ee--answering-p process url))
      (unless (process-live-p process)
        (ement-e2ee--drain process)
        (ement-e2ee--startup-failed "the proxy exited at start-up"))
      (when (> (float-time) deadline)
        (ement-e2ee--startup-failed
         (format "the proxy did not answer within %s seconds" ement-e2ee-startup-timeout)))
      (accept-process-output process 0.2))
    (ement-e2ee--mark-ready process)))

(defun ement-e2ee--when-ready (process url callback)
  "Call CALLBACK once PROCESS answers at URL, polling in the background."
  (ement-e2ee--cancel-ready-timer)
  (let ((deadline (+ (float-time) ement-e2ee-startup-timeout)))
    (cl-labels ((check ()
                  (setq ement-e2ee--ready-timer nil)
                  (cond ((not (process-live-p process)))
                        ((ement-e2ee--answering-p process url)
                         (ement-e2ee--mark-ready process)
                         (funcall callback))
                        ((> (float-time) deadline)
                         (display-warning
                          'ement-e2ee
                          (format "The proxy did not answer within %s seconds; see M-x ement-e2ee-log"
                                  ement-e2ee-startup-timeout)))
                        (t (setq ement-e2ee--ready-timer (run-at-time 0.2 nil #'check))))))
      (setq ement-e2ee--ready-timer (run-at-time 0.2 nil #'check)))))

(defun ement-e2ee--spawn-and-wait (program version url)
  "Start PROGRAM, of VERSION, and wait until it answers at URL."
  (setq ement-e2ee--quick-deaths 0
        ement-e2ee--backoff 0)
  (message "Ement-e2ee: starting the proxy...")
  (ement-e2ee--wait-ready (ement-e2ee--spawn program version nil) url)
  (message "Ement-e2ee: the proxy answers on %s" url))

(defun ement-e2ee--wait-gone (url)
  "Wait until nothing listens at URL any more."
  (let ((deadline (+ (float-time) 10)))
    (while (not (eq (ement-e2ee--probe url 1) 'nothing))
      (when (> (float-time) deadline)
        (user-error "Ement-e2ee: the proxy at %s did not stop within 10 seconds" url))
      (accept-process-output nil 0.2))))

(defun ement-e2ee--adopt (body program version url)
  "Use the proxy that answered BODY at URL, unless it is too old.
An old one is replaced by PROGRAM, of VERSION, if the user agrees."
  (let ((their-version (alist-get 'version body))
        (pid (alist-get 'pid body)))
    (if (and (not (ement-e2ee--new-enough-p their-version))
             (yes-or-no-p
              (format "The proxy at %s (pid %s) is ement-e2ee %s, older than %s.  Replace it? "
                      url pid their-version ement-e2ee-binary-version)))
        (progn
          (signal-process pid 'SIGTERM)
          (ement-e2ee--wait-gone url)
          (ement-e2ee--spawn-and-wait program version url))
      (setq ement-e2ee--adopted body)
      (ement-e2ee--start-watchdog))))

(defun ement-e2ee--ensure ()
  "Make sure a proxy is running and answering; return its URL.
Use the one this Emacs started, else one that is already running,
else start one."
  (let* ((program (ement-e2ee--program))
         (info (ement-e2ee--info program))
         (url (alist-get 'url info))
         (version (alist-get 'version info)))
    (unless (alist-get 'homeserver info)
      (user-error "Ement-e2ee: %s names no homeserver; M-x ement-e2ee-setup writes one"
                  (alist-get 'config_file info)))
    (setq ement-e2ee--url url)
    ;; A restart about to happen in the background happens here instead.
    (when (timerp ement-e2ee--restart-timer)
      (cancel-timer ement-e2ee--restart-timer)
      (setq ement-e2ee--restart-timer nil))
    (cond
     ((process-live-p ement-e2ee--process)
      (cond ((not (ement-e2ee--new-enough-p (process-get ement-e2ee--process 'version)))
             (message "Ement-e2ee: restarting the proxy, which is older than %s"
                      ement-e2ee-binary-version)
             (ement-e2ee--stop-and-wait)
             (ement-e2ee--spawn-and-wait program version url))
            ((not (process-get ement-e2ee--process 'ready))
             (ement-e2ee--wait-ready ement-e2ee--process url))))
     (t
      (pcase (ement-e2ee--probe url)
        (`(proxy . ,body) (ement-e2ee--adopt body program version url))
        ('nothing
         ;; Timers run while the probe waits; one may have started a proxy.
         (if (process-live-p ement-e2ee--process)
             (ement-e2ee--wait-ready ement-e2ee--process url)
           (ement-e2ee--spawn-and-wait program version url)))
        (`(other . ,what)
         (user-error "Ement-e2ee: %s is in use by something else (%s)" url what)))))
    url))

(defun ement-e2ee--cancel-ready-timer ()
  "Stop waiting for a proxy started in the background."
  (when (timerp ement-e2ee--ready-timer)
    (cancel-timer ement-e2ee--ready-timer))
  (setq ement-e2ee--ready-timer nil))

(defun ement-e2ee--start-watchdog ()
  "Check on the adopted proxy from time to time."
  (unless (timerp ement-e2ee--watchdog-timer)
    (setq ement-e2ee--watchdog-timer
          (run-at-time ement-e2ee--watchdog-interval ement-e2ee--watchdog-interval
                       #'ement-e2ee--watchdog))))

(defun ement-e2ee--cancel-watchdog ()
  "Stop checking on an adopted proxy."
  (when (timerp ement-e2ee--watchdog-timer)
    (cancel-timer ement-e2ee--watchdog-timer))
  (setq ement-e2ee--watchdog-timer nil))

(defun ement-e2ee--cancel-timers ()
  "Cancel every pending restart, wait and check."
  (when (timerp ement-e2ee--restart-timer)
    (cancel-timer ement-e2ee--restart-timer))
  (setq ement-e2ee--restart-timer nil)
  (ement-e2ee--cancel-ready-timer)
  (ement-e2ee--cancel-watchdog))

(defun ement-e2ee--watchdog ()
  "Replace an adopted proxy that has gone, while ement needs one."
  (when (and ement-e2ee--adopted ement-e2ee--url)
    (pcase (ement-e2ee--probe ement-e2ee--url)
      ('nothing
       (setq ement-e2ee--adopted nil)
       (ement-e2ee--cancel-watchdog)
       (when (ement-e2ee--routed-sessions)
         (ement-e2ee--log-note "the proxy found running is gone; starting one")
         (condition-case err
             (ement-e2ee--start-async)
           (error (display-warning 'ement-e2ee
                                   (format "Could not start the proxy: %s"
                                           (error-message-string err))
                                   :error)))))
      (`(proxy . ,body) (setq ement-e2ee--adopted body)))))

(defun ement-e2ee--stop-and-wait ()
  "Stop the proxy this Emacs started, and wait until it has exited."
  (let ((process ement-e2ee--process)
        (deadline (+ (float-time) 10)))
    (ement-e2ee-stop)
    (while (and (process-live-p process) (< (float-time) deadline))
      (accept-process-output process 0.1))
    (when (process-live-p process)
      (user-error "Ement-e2ee: the proxy did not stop within 10 seconds"))))

;;;; ement integration

(defun ement-e2ee--routed-p (user-id)
  "Whether `ement-e2ee-accounts' routes USER-ID through the proxy."
  (or (eq ement-e2ee-accounts t)
      (and user-id (member user-id ement-e2ee-accounts) t)))

(defun ement-e2ee--session-routed-p (session)
  "Whether ement's SESSION is routed through the proxy."
  (and ement-e2ee--url
       (equal (ement-server-uri-prefix (ement-session-server session)) ement-e2ee--url)))

(defun ement-e2ee--routed-sessions ()
  "Return ement's sessions that go through the proxy."
  (cl-loop for (_ . session) in (bound-and-true-p ement-sessions)
           when (ement-e2ee--session-routed-p session)
           collect session))

(defun ement-e2ee--resume-syncs ()
  "Sync again each session through the proxy that has stopped syncing.
ement gives up syncing when the proxy is unreachable for a moment."
  (dolist (session (ement-e2ee--routed-sessions))
    (unless (process-live-p (cdr (assq session (bound-and-true-p ement-syncs))))
      (condition-case err
          (ement-room-sync session t)
        (error (message "Ement-e2ee: could not sync %s again: %s"
                        (ement-user-id (ement-session-user session))
                        (error-message-string err)))))))

(defun ement-e2ee--prepare (user-id)
  "Get the proxy ready for USER-ID to connect through; return its URL.
Install the binary and write the config first if need be."
  (let ((program (or (ement-e2ee--locate-binary)
                     (pcase ement-e2ee-auto-install
                       ('nil (user-error "Ement-e2ee: the proxy is not installed; \
M-x ement-e2ee-install installs it"))
                       (mode (let ((binary (ement-e2ee--obtain-binary (eq mode t))))
                               (if (stringp binary)
                                   binary
                                 (user-error "Ement-e2ee: building the proxy; \
connect again once that is done"))))))))
    (ement-e2ee--ensure-config program user-id)
    (ement-e2ee--ensure)))

(defun ement-e2ee--connect-advice (connect &rest args)
  "Have CONNECT, `ement-connect', called with ARGS, go through the proxy.
For accounts `ement-e2ee-accounts' routes, start the proxy if
need be and use it as the server's URI prefix, overriding any
:uri-prefix given and the one a saved session has."
  (ement-e2ee--add-hooks)
  (let* ((session (plist-get args :session))
         (user-id (if session
                      (ement-user-id (ement-session-user session))
                    (plist-get args :user-id))))
    (unless user-id
      ;; As ement would ask anyway, ask first: routing depends on it.
      (setq user-id (read-string "User ID: " nil 'ement-connect-user-id-history)
            args (plist-put (copy-sequence args) :user-id user-id)))
    (if (not (ement-e2ee--routed-p user-id))
        (apply connect args)
      (let ((url (ement-e2ee--prepare user-id)))
        (if session
            (let ((server (ement-session-server session)))
              (aset server (cl-struct-slot-offset 'ement-server 'uri-prefix) url)
              (apply connect args))
          (apply connect (plist-put (copy-sequence args) :uri-prefix url)))))))

(defun ement-e2ee--on-disconnect ()
  "Stop the proxy when no session needs it, per `ement-e2ee-stop-on-disconnect'."
  (unless (ement-e2ee--routed-sessions)
    ;; One found running is not this Emacs's to stop, or to watch now.
    (ement-e2ee--cancel-watchdog)
    (setq ement-e2ee--adopted nil)
    (when (and ement-e2ee-stop-on-disconnect
               (process-live-p ement-e2ee--process))
      (ement-e2ee-stop))))

(defun ement-e2ee--bootstrap-hint (session)
  "Suggest `ement-e2ee-bootstrap' once if SESSION's device is not cross-signed."
  (let ((user-id (ement-user-id (ement-session-user session))))
    (when (and (ement-e2ee--session-routed-p session)
               (not (member user-id ement-e2ee--hinted)))
      (push user-id ement-e2ee--hinted)
      ;; This runs in ement's sync callback: never fail there.
      (with-demoted-errors "Ement-e2ee: no bootstrap hint: %S"
        (ement-e2ee--ctl-async
         '("status")
         (lambda (status output)
           (let* ((json (and (eq status 0) (ement-e2ee--json output)))
                  (entry (cl-find user-id (alist-get 'sessions json)
                                  :key (lambda (entry) (alist-get 'user_id entry))
                                  :test #'equal)))
             (when (and entry
                        (not (alist-get 'has_self_signing (alist-get 'cross_signing entry))))
               (message "Ement-e2ee: %s"
                        (substitute-command-keys
                         (format "%s is not cross-signed yet; \\[ement-e2ee-bootstrap] \
joins your encrypted identity" user-id)))))))))))

(defun ement-e2ee--add-hooks ()
  "Hook into ement's disconnection and initial sync."
  (add-hook 'ement-disconnect-hook #'ement-e2ee--on-disconnect 90)
  (add-hook 'ement-after-initial-sync-hook #'ement-e2ee--bootstrap-hint 90))

(defun ement-e2ee--remove-hooks ()
  "Undo `ement-e2ee--add-hooks'."
  (remove-hook 'ement-disconnect-hook #'ement-e2ee--on-disconnect)
  (remove-hook 'ement-after-initial-sync-hook #'ement-e2ee--bootstrap-hint))

;;;###autoload
(define-minor-mode ement-e2ee-mode
  "Route ement through the ement-e2ee proxy, for end-to-end encryption.
With the mode on, `ement-connect' sends the accounts
`ement-e2ee-accounts' names through the proxy, starting it when
it is not running yet (or installing it first, as
`ement-e2ee-auto-install' says).  This Emacs restarts the proxy
when it dies and resumes ement's syncs afterwards, and stops it
when the last session using it disconnects.

Turning the mode off leaves a running proxy alone (see
`ement-e2ee-stop'); sessions that ement saved keep its URL."
  :global t
  :group 'ement-e2ee
  (if ement-e2ee-mode
      (progn
        (advice-add 'ement-connect :around #'ement-e2ee--connect-advice)
        ;; Otherwise the advice adds them: not before ement is loaded,
        ;; or ement's own defaults for these hooks would never be set.
        (when (featurep 'ement)
          (ement-e2ee--add-hooks)))
    (advice-remove 'ement-connect #'ement-e2ee--connect-advice)
    (ement-e2ee--remove-hooks)))

;;;; Commands

;;;###autoload
(defun ement-e2ee-install (&optional force)
  "Get the ement-e2ee proxy ready and route ement through it.
Download or build the binary if there is none (with prefix
argument FORCE, even if there is), write the proxy's config if
it has none, and turn on `ement-e2ee-mode' if it is off,
offering to keep it on in future sessions.  Safe to run again."
  (interactive "P")
  (let ((binary (or (and (not force) (ement-e2ee--locate-binary))
                    (ement-e2ee--obtain-binary nil))))
    (when (stringp binary)
      (ement-e2ee--ensure-config binary)
      ;; A mode already on is on by the user's own arrangement (an init
      ;; file, say): no offer then, as after every build of an upgrade.
      (unless ement-e2ee-mode
        (ement-e2ee-mode 1)
        (when (and (not (equal (get 'ement-e2ee-mode 'saved-value) '(t)))
                   (y-or-n-p "Turn on `ement-e2ee-mode' in future Emacs sessions too \
\(saved with Customize)? "))
          (customize-save-variable 'ement-e2ee-mode t)))
      (message "Ement-e2ee: ready; M-x ement-connect goes through the proxy"))))

;;;###autoload
(defun ement-e2ee-setup (user-id)
  "Write the proxy's config afresh, for the account USER-ID.
The homeserver is found from the user ID; an existing config is
replaced."
  (interactive (list (ement-e2ee--read-user-id)))
  (ement-e2ee--setup (ement-e2ee--program) user-id t)
  (message "Ement-e2ee: wrote the config for %s" user-id)
  (when (and (process-live-p ement-e2ee--process)
             (y-or-n-p "Restart the proxy with the new config? "))
    (ement-e2ee-restart)))

(defun ement-e2ee-start ()
  "Start the proxy, unless one is running already."
  (interactive)
  (message "Ement-e2ee: the proxy answers on %s" (ement-e2ee--ensure)))

(defun ement-e2ee-stop ()
  "Stop the proxy.
It finishes the requests in flight first, for three seconds at
most.  A proxy this Emacs did not start is stopped only when
called interactively, after asking."
  (interactive)
  (ement-e2ee--cancel-timers)
  (cond
   ((process-live-p ement-e2ee--process)
    (setq ement-e2ee--stopping t)
    (signal-process ement-e2ee--process 'SIGTERM)
    (message "Ement-e2ee: stopping the proxy"))
   (ement-e2ee--adopted
    (let ((pid (alist-get 'pid ement-e2ee--adopted)))
      (when (and (called-interactively-p 'interactive)
                 (yes-or-no-p (format "The proxy (pid %s) was started outside this Emacs.  \
Stop it anyway? " pid)))
        (signal-process pid 'SIGTERM)
        (setq ement-e2ee--adopted nil))))
   ((called-interactively-p 'interactive)
    (message "Ement-e2ee: no proxy runs here"))))

(defun ement-e2ee-restart ()
  "Restart the proxy, then resume ement's syncs through it."
  (interactive)
  (cond ((process-live-p ement-e2ee--process)
         (ement-e2ee--stop-and-wait))
        (ement-e2ee--adopted
         (signal-process (alist-get 'pid ement-e2ee--adopted) 'SIGTERM)
         (setq ement-e2ee--adopted nil)
         (ement-e2ee--cancel-watchdog)
         (ement-e2ee--wait-gone ement-e2ee--url)))
  (ement-e2ee--ensure)
  (ement-e2ee--resume-syncs))

(defun ement-e2ee-delete-old-binaries ()
  "Delete the binaries `ement-e2ee-install' got for older versions.
Starting a proxy of the version this package needs does so too."
  (interactive)
  (let ((old (ement-e2ee--old-binary-directories)))
    (cond ((null old)
           (message "Ement-e2ee: no old binaries"))
          ((yes-or-no-p (format "Delete ement-e2ee %s? "
                                (mapconcat #'file-name-nondirectory old ", ")))
           (dolist (directory old)
             (delete-directory directory t))
           (message "Ement-e2ee: deleted %d old version(s)" (length old))))))

;;;; ctl

(defun ement-e2ee--ctl-args (args)
  "Return the command line arguments for \"ement-e2ee ctl ARGS\"."
  `("ctl" ,@(ement-e2ee--config-args) ,@args))

(defun ement-e2ee--ctl-async (args callback &optional input)
  "Run \"ement-e2ee ctl ARGS\" and call CALLBACK with its exit status and output.
Write INPUT, if any, to its standard input, then close it.  Never
wait for ctl: it has no timeout of its own."
  (let* ((buffer (generate-new-buffer " *ement-e2ee ctl*" t))
         (process (make-process
                   :name "ement-e2ee-ctl" :buffer buffer
                   :command (cons (ement-e2ee--program) (ement-e2ee--ctl-args args))
                   :connection-type 'pipe :noquery t :coding 'utf-8-unix
                   :sentinel (lambda (process _event)
                               (unless (process-live-p process)
                                 (let ((output (with-current-buffer buffer
                                                 (buffer-string))))
                                   (kill-buffer buffer)
                                   (funcall callback (process-exit-status process)
                                            output)))))))
    (when input
      (process-send-string process input))
    (process-send-eof process)
    process))

(define-derived-mode ement-e2ee-output-mode special-mode "ement-e2ee"
  "Major mode for what an ement-e2ee command printed.
\\<ement-e2ee-output-mode-map>\\[revert-buffer] runs the command again."
  (setq-local revert-buffer-function #'ement-e2ee--rerun))

(defvar-local ement-e2ee--output-args nil
  "The ctl arguments whose output this buffer shows.")

(defun ement-e2ee--rerun (&rest _)
  "Run again the ctl command whose output is in this buffer."
  (ement-e2ee--ctl-to-buffer ement-e2ee--output-args (buffer-name)))

(defun ement-e2ee--ctl-to-buffer (args buffer-name &optional input)
  "Run \"ement-e2ee ctl ARGS\" with INPUT and show its output in BUFFER-NAME."
  (message "Ement-e2ee: running ctl %s..." (car args))
  (ement-e2ee--ctl-async
   args
   (lambda (status output)
     (with-current-buffer (get-buffer-create buffer-name)
       (let ((inhibit-read-only t))
         (erase-buffer)
         (ement-e2ee-output-mode)
         (setq ement-e2ee--output-args args)
         (insert output)
         (goto-char (point-min)))
       (display-buffer (current-buffer))
       (message "Ement-e2ee: ctl %s %s" (car args)
                (if (eq status 0) "done" (format "exited with status %s" status)))))
   input))

(defun ement-e2ee--read-session-user-id ()
  "Return the user ID of the session to act on, or nil if there is one only."
  (let ((user-ids (mapcar (lambda (session) (ement-user-id (ement-session-user session)))
                          (ement-e2ee--routed-sessions))))
    (if (cdr user-ids)
        (completing-read "Session: " user-ids nil t)
      (car user-ids))))

(defun ement-e2ee--user-id-args (user-id)
  "Return the ctl arguments that pick USER-ID's session."
  (and user-id (list "--user-id" user-id)))

(defun ement-e2ee-status ()
  "Show the proxy's sessions, their cross-signing and key backup."
  (interactive)
  (ement-e2ee--ctl-to-buffer '("status") "*ement-e2ee status*"))

(defun ement-e2ee-check ()
  "Check everything from the homeserver to ement's syncing, with remedies."
  (interactive)
  (ement-e2ee--ctl-to-buffer '("debug" "check") "*ement-e2ee check*"))

(defun ement-e2ee-log ()
  "Show the proxy's log.
That is the output of the proxy this Emacs runs or ran, or else,
for one started elsewhere, the lines that proxy keeps in memory."
  (interactive)
  (let ((buffer (get-buffer ement-e2ee--log-buffer-name)))
    (if (and buffer (or (process-live-p ement-e2ee--process)
                        (not ement-e2ee--adopted)))
        (pop-to-buffer buffer)
      (ement-e2ee--ctl-to-buffer '("debug" "logs") "*ement-e2ee logs*"))))

(defun ement-e2ee-bootstrap (user-id)
  "Join your encrypted identity, with the recovery key, as USER-ID's device.
Import the cross-signing keys from secret storage, sign this
device and restore the room keys from the key backup."
  (interactive (list (ement-e2ee--read-session-user-id)))
  (let ((key (read-passwd "Recovery key (or passphrase): ")))
    (unwind-protect
        (ement-e2ee--ctl-to-buffer
         `("bootstrap" "--recovery-key-file" "/dev/stdin"
           ,@(ement-e2ee--user-id-args user-id))
         "*ement-e2ee bootstrap*" key)
      (clear-string key))))

(defun ement-e2ee-verify (user-id &optional device)
  "Emoji-verify USER-ID's device against another device of yours.
Without DEVICE, wait for a verification started on the other
device; with it, start one with that device ID.  ement has to
keep syncing meanwhile."
  (interactive
   (list (ement-e2ee--read-session-user-id)
         (let ((device (read-string "Start with device ID (empty: wait for the other device): ")))
           (and (not (string-empty-p device)) device))))
  (pop-to-buffer
   (apply #'make-comint-in-buffer "ement-e2ee-verify" "*ement-e2ee verify*"
          (ement-e2ee--program) nil
          (ement-e2ee--ctl-args `("verify" ,@(and device (list "--device" device))
                                  ,@(ement-e2ee--user-id-args user-id))))))

;; Customize can set the mode variable before this file is loaded (as
;; `ement-e2ee-install' offers); then nothing has turned the mode on.
(when ement-e2ee-mode
  (ement-e2ee-mode 1))

(provide 'ement-e2ee)

;;; ement-e2ee.el ends here
