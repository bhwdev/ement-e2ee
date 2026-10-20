;;; ement-e2ee-test.el --- Tests for ement-e2ee.el  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ben H. W.

;; SPDX-License-Identifier: GPL-3.0-or-later

;; This file is not part of GNU Emacs.

;;; Commentary:

;; Run in batch mode, with the parent directory, ement, plz and ement's
;; other dependencies on `load-path': load this file, then call
;; `ert-run-tests-batch-and-exit'.  The README has the command line.
;;
;; The tests that run a real proxy need EMENT_E2EE_TEST_PROGRAM, e.g.
;; target/debug/ement-e2ee after `cargo build'; without it they are
;; skipped.  None of them needs a network or a Matrix account.

;;; Code:

(require 'ert)
(require 'ement)
(require 'ement-e2ee)

(defconst ement-e2ee-test--directory
  (file-name-directory (or load-file-name buffer-file-name))
  "The directory of this file.")

(defvar ement-e2ee-test--program
  (when-let ((program (getenv "EMENT_E2EE_TEST_PROGRAM")))
    (expand-file-name program))
  "The real ement-e2ee binary to run, if any.")

;;;; Helpers

(defmacro ement-e2ee-test--with-temp-dir (var &rest body)
  "Bind VAR to a new temporary directory while running BODY."
  (declare (indent 1))
  `(let ((,var (file-name-as-directory (make-temp-file "ement-e2ee-test" t))))
     (unwind-protect (progn ,@body)
       (delete-directory ,var t))))

(defmacro ement-e2ee-test--with-state (&rest body)
  "Run BODY with this package's state fresh, and clean up after it."
  (declare (indent 0))
  `(let ((ement-e2ee--process nil)
         (ement-e2ee--adopted nil)
         (ement-e2ee--url nil)
         (ement-e2ee--stopping nil)
         (ement-e2ee--backoff 0)
         (ement-e2ee--quick-deaths 0)
         (ement-e2ee--restart-timer nil)
         (ement-e2ee--ready-timer nil)
         (ement-e2ee--watchdog-timer nil)
         (ement-e2ee--hinted nil)
         (ement-e2ee--backoff-unit 0.05)
         (ement-sessions nil)
         (ement-syncs nil))
     (unwind-protect (progn ,@body)
       ;; `delete-process' runs the sentinel at once: no restart, please.
       (setq ement-e2ee--stopping t)
       (dolist (process (process-list))
         (when (string-prefix-p "ement-e2ee" (process-name process))
           (delete-process process)))
       (ement-e2ee--cancel-timers)
       (when-let ((buffer (get-buffer ement-e2ee--log-buffer-name)))
         (kill-buffer buffer)))))

(defun ement-e2ee-test--fake-binary (file version)
  "Write to FILE a script claiming to be ement-e2ee VERSION; return FILE."
  (make-directory (file-name-directory file) t)
  (with-temp-file file
    (insert (format "#!/bin/sh\necho 'ement-e2ee %s'\n" version)))
  (set-file-modes file #o755)
  file)

(defun ement-e2ee-test--free-port ()
  "Return a local port nothing listens on (released just now)."
  (let* ((server (make-network-process :name "ement-e2ee-test-port" :server t
                                       :host "127.0.0.1" :service t :family 'ipv4
                                       :noquery t))
         (port (process-contact server :service)))
    (delete-process server)
    port))

(defun ement-e2ee-test--write-config (directory port &optional extra)
  "Write a proxy config into DIRECTORY for PORT, with EXTRA lines; return it.
Its homeserver is a port where nothing answers."
  (let ((config (expand-file-name "config.toml" directory)))
    (with-temp-file config
      (insert (format "listen = \"127.0.0.1:%d\"\nhomeserver = \"http://127.0.0.1:%d\"\n\
store_dir = \"%s\"\n%s\n"
                      port (ement-e2ee-test--free-port)
                      (expand-file-name "store" directory)
                      (or extra ""))))
    config))

(defun ement-e2ee-test--wait-for (predicate seconds)
  "Wait until PREDICATE yields non-nil, for SECONDS at most; return that."
  (let ((deadline (+ (float-time) seconds))
        value)
    (while (and (not (setq value (funcall predicate)))
                (< (float-time) deadline))
      (accept-process-output nil 0.05))
    value))

(defun ement-e2ee-test--log ()
  "Return the contents of the log buffer."
  (with-current-buffer ement-e2ee--log-buffer-name
    (buffer-string)))

(defun ement-e2ee-test--session (user-id uri-prefix)
  "Return an ement session for USER-ID whose server is at URI-PREFIX."
  (make-ement-session
   :user (make-ement-user :id user-id :username "me")
   :server (make-ement-server :name "example.org" :uri-prefix uri-prefix)
   :token "token" :transaction-id 1 :events (make-hash-table :test #'equal)))

;;;; Versions and targets

(ert-deftest ement-e2ee-test-version-parsing ()
  (should (equal (ement-e2ee--parse-version "ement-e2ee 0.18.0\n") "0.18.0"))
  (should (equal (ement-e2ee--parse-version "ement-e2ee 0.19.0-rc.1\n") "0.19.0-rc.1"))
  (should (equal (ement-e2ee--parse-version "ement-e2ee 0.19.0+build.7\n") "0.19.0+build.7"))
  (dolist (output '("" "ement-e2ee\n" "something 0.18.0\n" "ement-e2ee banana\n"
                    "ement-e2ee 0.18.0 extra\n" "ement-e2ee v0.18.0\n"))
    (should-not (ement-e2ee--parse-version output))))

(ert-deftest ement-e2ee-test-version-comparison ()
  (let ((ement-e2ee-binary-version "0.18.0"))
    (dolist (version '("0.18.0" "0.18.1" "0.19.0" "1.0.0" "0.18.10"))
      (should (ement-e2ee--new-enough-p version)))
    ;; A pre-release comes before its release.
    (dolist (version '("0.17.9" "0.1.0" "0.18.0-rc.1" "garbage" "" nil))
      (should-not (ement-e2ee--new-enough-p version)))
    (should (ement-e2ee--new-enough-p "0.18.1-rc.1"))
    (should (ement-e2ee--new-enough-p "0.18.0+build.7")))
  (should (ement-e2ee--version< "0.9.0" "0.18.0"))
  (should-not (ement-e2ee--version< "0.18.0" "0.18.0"))
  (should-not (ement-e2ee--version< "garbage" "0.18.0")))

(ert-deftest ement-e2ee-test-target ()
  (cl-flet ((target (configuration type)
              (let ((system-configuration configuration)
                    (system-type type))
                (ement-e2ee--target))))
    (should (equal (target "x86_64-pc-linux-gnu" 'gnu/linux) "x86_64-unknown-linux-musl"))
    (should (equal (target "aarch64-unknown-linux-gnu" 'gnu/linux) "aarch64-unknown-linux-musl"))
    (should (equal (target "aarch64-apple-darwin23.1.0" 'darwin) "aarch64-apple-darwin"))
    (should (equal (target "arm64-apple-darwin22.6.0" 'darwin) "aarch64-apple-darwin"))
    ;; No prebuilt binary: Intel macOS, other systems, other CPUs.
    (should-not (target "x86_64-apple-darwin21.6.0" 'darwin))
    (should-not (target "x86_64-w64-mingw32" 'windows-nt))
    (should-not (target "amd64-unknown-freebsd14.0" 'berkeley-unix))
    (should-not (target "riscv64-unknown-linux-gnu" 'gnu/linux))))

;;;; Resolution

(ert-deftest ement-e2ee-test-resolution-order ()
  (ement-e2ee-test--with-temp-dir dir
    (let* ((on-path (expand-file-name "path/ement-e2ee" dir))
           (exec-path (list (file-name-directory on-path)))
           (ement-e2ee-binary-directory (expand-file-name "managed/" dir))
           (ement-e2ee-binary-version "0.18.0")
           (managed (ement-e2ee--managed-binary))
           (ement-e2ee-program nil))
      (should (equal managed (expand-file-name "managed/0.18.0/bin/ement-e2ee" dir)))
      (should-not (ement-e2ee--locate-binary))
      (should-error (ement-e2ee--program) :type 'user-error)
      (ement-e2ee-test--fake-binary managed "0.18.0")
      (should (equal (ement-e2ee--locate-binary) managed))
      ;; A stale binary on PATH (an old `cargo install') is passed over ...
      (ement-e2ee-test--fake-binary on-path "0.1.0")
      (should (equal (ement-e2ee--locate-binary) managed))
      (ement-e2ee-test--fake-binary on-path "nonsense")
      (should (equal (ement-e2ee--locate-binary) managed))
      ;; ... a new enough one wins.
      (ement-e2ee-test--fake-binary on-path "0.18.1")
      (should (equal (ement-e2ee--locate-binary) on-path))
      ;; The user's choice comes first, but has to be new enough too.
      (let ((ement-e2ee-program
             (ement-e2ee-test--fake-binary (expand-file-name "mine/ement-e2ee" dir) "0.19.0")))
        (should (equal (ement-e2ee--locate-binary) ement-e2ee-program)))
      (let ((ement-e2ee-program
             (ement-e2ee-test--fake-binary (expand-file-name "old/ement-e2ee" dir) "0.17.0")))
        (should-error (ement-e2ee--locate-binary) :type 'user-error))
      (let ((ement-e2ee-program (expand-file-name "missing/ement-e2ee" dir)))
        (should-error (ement-e2ee--locate-binary) :type 'user-error)))))

(ert-deftest ement-e2ee-test-old-binaries ()
  (ement-e2ee-test--with-temp-dir dir
    (let* ((ement-e2ee-binary-directory (expand-file-name "managed/" dir))
           (ement-e2ee-binary-version "0.18.0")
           (exec-path nil)
           (managed (lambda (version) (ement-e2ee--managed-binary version))))
      (should-not (ement-e2ee--old-binary-directories))
      (should-not (ement-e2ee--older-version))
      ;; Downloaded; built by cargo; a download that failed half-way.
      (ement-e2ee-test--fake-binary (funcall managed "0.17.0") "0.17.0")
      (ement-e2ee-test--fake-binary (funcall managed "0.17.1") "0.17.1")
      (dolist (record '(".crates.toml" ".crates2.json"))
        (write-region "" nil (expand-file-name (concat "0.17.1/" record)
                                               ement-e2ee-binary-directory)))
      (make-directory (expand-file-name "0.16.0/bin" ement-e2ee-binary-directory) t)
      (write-region "" nil (concat (funcall managed "0.16.0") ".part"))
      ;; Not old, or not this package's.
      (ement-e2ee-test--fake-binary (funcall managed "0.18.0") "0.18.0")
      (ement-e2ee-test--fake-binary (funcall managed "0.19.0") "0.19.0")
      (make-directory (expand-file-name "0.17.5" ement-e2ee-binary-directory) t)
      (write-region "" nil (expand-file-name "0.17.5/notes.txt" ement-e2ee-binary-directory))
      (should (equal (mapcar #'file-name-nondirectory (ement-e2ee--old-binary-directories))
                     '("0.16.0" "0.17.0" "0.17.1")))
      (should (equal (ement-e2ee--older-version) "0.17.1"))
      ;; An older one on PATH counts too, a new enough one does not.
      (let ((exec-path (list (expand-file-name "path/" dir))))
        (ement-e2ee-test--fake-binary (expand-file-name "path/ement-e2ee" dir) "0.17.9")
        (should (equal (ement-e2ee--older-version) "0.17.9"))
        (ement-e2ee-test--fake-binary (expand-file-name "path/ement-e2ee" dir) "0.18.1")
        (should (equal (ement-e2ee--older-version) "0.17.1")))
      (ement-e2ee--delete-superseded-binaries)
      (should (equal (directory-files ement-e2ee-binary-directory nil (rx bos digit))
                     '("0.17.5" "0.18.0" "0.19.0")))
      (should (file-exists-p (expand-file-name "0.17.5/notes.txt" ement-e2ee-binary-directory))))))

(ert-deftest ement-e2ee-test-obtain-question ()
  (ement-e2ee-test--with-temp-dir dir
    (let ((ement-e2ee-binary-directory (expand-file-name "managed/" dir))
          (ement-e2ee-binary-version "0.18.0")
          (exec-path nil))
      (should (equal (ement-e2ee--obtain-question)
                     "ement-e2ee 0.18.0 is not installed.  Get it?"))
      ;; After an upgrade of this package.
      (ement-e2ee-test--fake-binary (ement-e2ee--managed-binary "0.17.0") "0.17.0")
      (should (equal (ement-e2ee--obtain-question)
                     "ement-e2ee.el now needs ement-e2ee 0.18.0 (installed: 0.17.0).  Get it?"))
      ;; C-u M-x ement-e2ee-install.
      (ement-e2ee-test--fake-binary (ement-e2ee--managed-binary) "0.18.0")
      (should (equal (ement-e2ee--obtain-question) "Get ement-e2ee 0.18.0 again?")))))

(ert-deftest ement-e2ee-test-install-offers-customize-only-when-turning-the-mode-on ()
  (ement-e2ee-test--with-temp-dir dir
    (let ((ement-e2ee-program
           (ement-e2ee-test--fake-binary (expand-file-name "ement-e2ee" dir) "0.18.0"))
          (ement-e2ee-binary-version "0.18.0")
          (asked 0))
      (cl-letf (((symbol-function 'ement-e2ee--ensure-config) #'ignore)
                ((symbol-function 'y-or-n-p) (lambda (_) (cl-incf asked) nil))
                ((symbol-function 'customize-save-variable)
                 (lambda (&rest _) (error "Saved with Customize"))))
        ;; On already, from an init file, say; or after a build.
        (let ((ement-e2ee-mode t))
          (ement-e2ee-install))
        (should (= asked 0))
        (let ((ement-e2ee-mode nil))
          (unwind-protect
              (progn (ement-e2ee-install)
                     (should ement-e2ee-mode))
            (ement-e2ee-mode -1)))
        (should (= asked 1))))))

;;;; Download

(defconst ement-e2ee-test--target "x86_64-unknown-linux-musl"
  "The target the download tests use.")

(defun ement-e2ee-test--release (dir version &optional sums)
  "Make a release of VERSION in DIR and return its URL format.
It has a fake binary for `ement-e2ee-test--target' and SHA256SUMS,
whose text is SUMS if given."
  (let* ((release (expand-file-name (format "releases/v%s/" version) dir))
         (asset (concat "ement-e2ee-" ement-e2ee-test--target))
         (binary (ement-e2ee-test--fake-binary (expand-file-name asset release) version)))
    (with-temp-file (expand-file-name "SHA256SUMS" release)
      (insert (or sums
                  (format "%s  ement-e2ee-aarch64-apple-darwin\n%s  %s\n"
                          (make-string 64 ?0)
                          (with-temp-buffer
                            (set-buffer-multibyte nil)
                            (insert-file-contents-literally binary)
                            (secure-hash 'sha256 (current-buffer)))
                          asset))))
    (concat "file://" (expand-file-name "releases/v%s/" dir))))

(ert-deftest ement-e2ee-test-download ()
  (ement-e2ee-test--with-temp-dir dir
    (let* ((ement-e2ee-release-url (ement-e2ee-test--release dir "0.18.0"))
           (ement-e2ee-binary-directory (expand-file-name "managed/" dir))
           (binary (ement-e2ee--download ement-e2ee-test--target "0.18.0")))
      (should (equal binary (ement-e2ee--managed-binary "0.18.0")))
      (should (file-executable-p binary))
      (should (equal (ement-e2ee--binary-version binary) "0.18.0"))
      (should-not (file-exists-p (concat binary ".part")))
      ;; Again (C-u M-x ement-e2ee-install): replaced in place.
      (should (equal (ement-e2ee--download ement-e2ee-test--target "0.18.0") binary)))))

(ert-deftest ement-e2ee-test-download-with-a-bad-checksum-leaves-nothing ()
  (ement-e2ee-test--with-temp-dir dir
    (let* ((ement-e2ee-release-url
            (ement-e2ee-test--release
             dir "0.18.0"
             (format "%s *ement-e2ee-%s\n" (make-string 64 ?a) ement-e2ee-test--target)))
           (ement-e2ee-binary-directory (expand-file-name "managed/" dir))
           (binary (ement-e2ee--managed-binary "0.18.0")))
      (should (string-match-p "Checksum mismatch"
                              (cadr (should-error (ement-e2ee--download
                                                   ement-e2ee-test--target "0.18.0")))))
      (should-not (file-exists-p binary))
      (should-not (file-exists-p (concat binary ".part"))))))

(ert-deftest ement-e2ee-test-download-of-a-missing-file-leaves-nothing ()
  (ement-e2ee-test--with-temp-dir dir
    (let* ((ement-e2ee-release-url (ement-e2ee-test--release dir "0.18.0"))
           (ement-e2ee-binary-directory (expand-file-name "managed/" dir))
           (binary (ement-e2ee--managed-binary "0.18.0")))
      ;; Listed, but not there (a 404, over HTTP).
      (delete-file (expand-file-name (concat "releases/v0.18.0/ement-e2ee-" ement-e2ee-test--target)
                                     dir))
      (should (string-match-p "Could not fetch"
                              (cadr (should-error (ement-e2ee--download
                                                   ement-e2ee-test--target "0.18.0")))))
      (should-not (file-exists-p binary))
      (should-not (file-exists-p (concat binary ".part")))
      ;; Not even listed; no release at all.
      (should (string-match-p "lists no ement-e2ee-riscv64"
                              (cadr (should-error (ement-e2ee--download
                                                   "riscv64-unknown-linux-musl" "0.18.0")))))
      (should-error (ement-e2ee--download ement-e2ee-test--target "9.9.9")))))

(ert-deftest ement-e2ee-test-download-of-the-wrong-version-is-rejected ()
  (ement-e2ee-test--with-temp-dir dir
    ;; A release whose binary says it is another version.
    (let* ((ement-e2ee-release-url (ement-e2ee-test--release dir "0.18.0"))
           (ement-e2ee-binary-directory (expand-file-name "managed/" dir)))
      (rename-file (expand-file-name "releases/v0.18.0" dir)
                   (expand-file-name "releases/v0.18.1" dir))
      (should-error (ement-e2ee--download ement-e2ee-test--target "0.18.1"))
      (should-not (file-exists-p (ement-e2ee--managed-binary "0.18.1"))))))

(ert-deftest ement-e2ee-test-download-of-an-unpublished-release-says-so ()
  (ement-e2ee-test--with-temp-dir dir
    (let ((ement-e2ee-binary-directory (expand-file-name "managed/" dir))
          (curl-error "curl: (22) The requested URL returned error: 404"))
      ;; What GitHub answers for a release that is not there (yet).
      (cl-letf (((symbol-function 'ement-e2ee--fetch)
                 (lambda (url &rest _) (error "Could not fetch %s: %s" url curl-error))))
        (let ((error (should-error (ement-e2ee--download ement-e2ee-test--target "0.18.1")
                                   :type 'user-error)))
          (should (string-match-p "ement-e2ee 0.18.1 has no release at .* yet" (cadr error))))
        ;; Any other failure is passed on as it is.
        (setq curl-error "curl: (6) Could not resolve host: github.com")
        (let ((error (should-error (ement-e2ee--download ement-e2ee-test--target "0.18.1"))))
          (should (string-match-p "Could not resolve host" (cadr error)))))
      ;; Not even an empty directory for that version.
      (should-not (file-exists-p (expand-file-name "0.18.1" ement-e2ee-binary-directory))))))

;;;; Build

(ert-deftest ement-e2ee-test-build-command ()
  (let ((ement-e2ee-binary-directory "/managed/")
        (ement-e2ee-binary-version "0.18.0"))
    (cl-letf (((symbol-function 'ement-e2ee--checkout) (lambda () "/src/my ement-e2ee/")))
      (should (equal (split-string-shell-command (ement-e2ee--build-command "/bin/cargo"))
                     '("/bin/cargo" "install" "--locked" "--root" "/managed/0.18.0"
                       "--path" "/src/my ement-e2ee/"))))
    (cl-letf (((symbol-function 'ement-e2ee--checkout) #'ignore))
      (should (equal (split-string-shell-command (ement-e2ee--build-command "/bin/cargo"))
                     '("/bin/cargo" "install" "--locked" "--root" "/managed/0.18.0"
                       "--git" "https://github.com/bhwdev/ement-e2ee" "--tag" "v0.18.0"))))))

(ert-deftest ement-e2ee-test-checkout-must-match-the-version ()
  ;; This repository is a checkout; whether it counts depends on its
  ;; Cargo.toml, which carries the same version as the package.
  (let ((manifest (expand-file-name "../Cargo.toml" ement-e2ee-test--directory)))
    (skip-unless (file-exists-p manifest))
    (should (equal (ement-e2ee--manifest-version manifest) ement-e2ee-binary-version))
    (should (ement-e2ee--checkout))
    (let ((ement-e2ee-binary-version "0.0.1"))
      (should-not (ement-e2ee--checkout)))))

;;;; Log buffer

(ert-deftest ement-e2ee-test-log-is-bounded ()
  (ement-e2ee-test--with-state
    (let ((ement-e2ee-log-max-lines 10))
      (ement-e2ee--log-buffer)
      (dotimes (i 50)
        (ement-e2ee--log-insert (format "line %d\n" i)))
      (with-current-buffer ement-e2ee--log-buffer-name
        (should (<= (count-lines (point-min) (point-max)) 11))
        (should (string-suffix-p "line 49\n" (buffer-string))))
      (should (equal (ement-e2ee--log-tail 2) "line 48\nline 49")))))

;;;; Probing

(ert-deftest ement-e2ee-test-probe-tells-what-listens ()
  (let ((port (ement-e2ee-test--free-port)))
    (should (eq (ement-e2ee--probe (format "http://127.0.0.1:%d" port)) 'nothing)))
  ;; Something that accepts and never answers (and, for curl, a loopback
  ;; port that WSL2's mirrored networking leaves hanging): a timeout.
  (let* ((server (make-network-process
                  :name "ement-e2ee-test-server" :server t :host "127.0.0.1" :service t
                  :family 'ipv4 :noquery t :filter #'ignore))
         (url (format "http://127.0.0.1:%d" (process-contact server :service)))
         (start (float-time)))
    (unwind-protect
        (should (eq (ement-e2ee--probe url 1) 'nothing))
      (delete-process server))
    (should (< (- (float-time) start) 3)))
  ;; Some other web server.
  (let* ((server (make-network-process
                  :name "ement-e2ee-test-server" :server t :host "127.0.0.1" :service t
                  :family 'ipv4 :noquery t
                  :filter (lambda (connection _)
                            (process-send-string
                             connection
                             "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
                            (process-send-eof connection))))
         (url (format "http://127.0.0.1:%d" (process-contact server :service))))
    (unwind-protect
        (pcase (ement-e2ee--probe url)
          (`(other . ,what) (should (string-match-p "HTTP 404" what)))
          (result (ert-fail (list "not classified as something else" result))))
      (delete-process server))))

;;;; ement integration

(ert-deftest ement-e2ee-test-advice-routes-a-new-login ()
  (ement-e2ee-test--with-state
    (let ((ement-e2ee-accounts t)
          prepared login-session)
      (cl-letf (((symbol-function 'ement-e2ee--prepare)
                 (lambda (user-id) (setq prepared user-id) "http://127.0.0.1:9999"))
                ((symbol-function 'ement-api)
                 (lambda (session &rest _) (setq login-session session) nil)))
        (ement-e2ee-mode 1)
        (unwind-protect
            (ement-connect :user-id "@me:example.org" :password "secret"
                           :uri-prefix "https://ignored.example.org")
          (ement-e2ee-mode -1)))
      (should (equal prepared "@me:example.org"))
      (should (equal (ement-server-uri-prefix (ement-session-server login-session))
                     "http://127.0.0.1:9999")))))

(ert-deftest ement-e2ee-test-advice-routes-a-saved-session ()
  (ement-e2ee-test--with-state
    (let ((ement-e2ee-accounts '("@me:example.org"))
          (session (ement-e2ee-test--session "@me:example.org" "https://matrix.example.org"))
          synced)
      (cl-letf (((symbol-function 'ement-e2ee--prepare) (lambda (_) "http://127.0.0.1:9999"))
                ((symbol-function 'ement--sync) (lambda (session &rest _) (setq synced session))))
        (ement-e2ee-mode 1)
        (unwind-protect
            (ement-connect :session session)
          (ement-e2ee-mode -1)))
      (should (eq synced session))
      (should (equal (ement-server-uri-prefix (ement-session-server session))
                     "http://127.0.0.1:9999")))))

(ert-deftest ement-e2ee-test-advice-leaves-other-accounts-alone ()
  (ement-e2ee-test--with-state
    (let ((ement-e2ee-accounts '("@someone-else:example.org"))
          (session (ement-e2ee-test--session "@me:example.org" "https://matrix.example.org")))
      (cl-letf (((symbol-function 'ement-e2ee--prepare)
                 (lambda (_) (error "Prepared a proxy for an account not routed")))
                ((symbol-function 'ement--sync) #'ignore))
        (ement-e2ee-mode 1)
        (unwind-protect
            (ement-connect :session session)
          (ement-e2ee-mode -1)))
      (should (equal (ement-server-uri-prefix (ement-session-server session))
                     "https://matrix.example.org")))))

(ert-deftest ement-e2ee-test-mode-off-removes-the-advice ()
  (ement-e2ee-mode 1)
  (ement-e2ee-mode -1)
  (should-not (advice-member-p #'ement-e2ee--connect-advice 'ement-connect))
  (should-not (memq #'ement-e2ee--on-disconnect ement-disconnect-hook))
  ;; ement's own hook functions are still there.
  (should (memq #'ement-kill-buffers ement-disconnect-hook)))

(ert-deftest ement-e2ee-test-resume-syncs-only-stalled-routed-sessions ()
  (ement-e2ee-test--with-state
    (let* ((ement-e2ee--url "http://127.0.0.1:9999")
           (stalled (ement-e2ee-test--session "@a:example.org" ement-e2ee--url))
           (syncing (ement-e2ee-test--session "@b:example.org" ement-e2ee--url))
           (direct (ement-e2ee-test--session "@c:example.org" "https://example.org"))
           (live (make-process :name "ement-e2ee-test-sync" :command '("sleep" "30")
                               :noquery t))
           resumed)
      (setq ement-sessions `(("@a:example.org" . ,stalled)
                             ("@b:example.org" . ,syncing)
                             ("@c:example.org" . ,direct))
            ement-syncs `((,syncing . ,live)))
      (unwind-protect
          (cl-letf (((symbol-function 'ement-room-sync)
                     (lambda (session &optional _) (push session resumed))))
            (ement-e2ee--resume-syncs))
        (delete-process live))
      (should (equal resumed (list stalled))))))

;;;; A real proxy

(defmacro ement-e2ee-test--with-proxy (config-var port-var extra &rest body)
  "Run BODY with a config for a real proxy, in fresh state.
CONFIG-VAR is bound to its file, PORT-VAR to its port; EXTRA is
more config."
  (declare (indent 3))
  (let ((dir (make-symbol "dir")))
    `(progn
       (skip-unless ement-e2ee-test--program)
       (ement-e2ee-test--with-temp-dir ,dir
         (ement-e2ee-test--with-state
           (let* ((,port-var (ement-e2ee-test--free-port))
                  (,config-var (ement-e2ee-test--write-config ,dir ,port-var ,extra))
                  (ement-e2ee-program ement-e2ee-test--program)
                  (ement-e2ee-config-file ,config-var)
                  ;; A started proxy deletes older binaries here.
                  (ement-e2ee-binary-directory (expand-file-name "managed/" ,dir))
                  (ement-e2ee-binary-version (ement-e2ee--binary-version
                                              ement-e2ee-test--program)))
             ,@body))))))

(ert-deftest ement-e2ee-test-proxy-lifecycle ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config)
    (let* ((url (ement-e2ee--ensure))
           (process ement-e2ee--process))
      ;; Started, and answering.
      (should (equal url (format "http://127.0.0.1:%d" port)))
      (should (process-live-p process))
      (should (process-get process 'ready))
      (should (string-match-p "--exit-on-stdin-close"
                              (mapconcat #'identity (process-command process) " ")))
      ;; Asked again, it is the same.
      (should (equal (ement-e2ee--ensure) url))
      (should (eq ement-e2ee--process process))
      ;; Another Emacs finds it running and uses it.
      (let ((ement-e2ee--process nil))
        (should (equal (ement-e2ee--ensure) url))
        (should-not ement-e2ee--process)
        (should (eql (alist-get 'pid ement-e2ee--adopted) (process-id process)))
        (should (timerp ement-e2ee--watchdog-timer))
        (ement-e2ee--cancel-watchdog)
        (setq ement-e2ee--adopted nil))
      ;; The last session gone, it stops: SIGTERM, a clean exit.
      (ement-e2ee--on-disconnect)
      (should (ement-e2ee-test--wait-for (lambda () (not (process-live-p process))) 10))
      (ement-e2ee--drain process)
      (should (eq (process-exit-status process) 0))
      (should (string-match-p "terminated; shutting down" (ement-e2ee-test--log)))
      (should-not ement-e2ee--process)
      (should-not (timerp ement-e2ee--restart-timer))
      (should (eq (ement-e2ee--probe url) 'nothing)))))

(ert-deftest ement-e2ee-test-proxy-older-than-needed-is-replaced ()
  ;; This package was upgraded, and reloaded, while its proxy ran.
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (let* ((url (ement-e2ee--ensure))
           (old ement-e2ee--process))
      (process-put old 'version "0.0.1")
      (should (equal (ement-e2ee--ensure) url))
      (should-not (process-live-p old))
      (should (process-live-p ement-e2ee--process))
      (should-not (eq ement-e2ee--process old))
      (should (process-get ement-e2ee--process 'ready))
      (should (eq (car (ement-e2ee--probe url)) 'proxy)))))

(ert-deftest ement-e2ee-test-proxy-start-deletes-older-binaries ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (let ((old (ement-e2ee-test--fake-binary (ement-e2ee--managed-binary "0.0.1") "0.0.1"))
          (newer (ement-e2ee-test--fake-binary (ement-e2ee--managed-binary "99.0.0") "99.0.0")))
      (ement-e2ee--ensure)
      (should-not (file-exists-p (file-name-directory (directory-file-name
                                                       (file-name-directory old)))))
      (should (file-exists-p newer))
      (should (string-match-p "deleted the binaries of ement-e2ee 0.0.1"
                              (ement-e2ee-test--log))))))

(ert-deftest ement-e2ee-test-proxy-is-restarted-after-kill ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (let* ((url (ement-e2ee--ensure))
           (first ement-e2ee--process)
           resumed)
      (cl-letf (((symbol-function 'ement-e2ee--resume-syncs) (lambda () (setq resumed t))))
        (signal-process first 'SIGKILL)
        (should (ement-e2ee-test--wait-for
                 (lambda () (and ement-e2ee--process
                                 (not (eq ement-e2ee--process first))
                                 (process-get ement-e2ee--process 'ready)))
                 20))
        (should resumed))
      (should (string-match-p "restarting in" (ement-e2ee-test--log)))
      (should (eq (car (ement-e2ee--probe url)) 'proxy))
      ;; A restarted proxy is supervised as well.
      (should (process-get ement-e2ee--process 'supervised)))))

(ert-deftest ement-e2ee-test-proxy-connecting-during-a-pending-restart ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (ement-e2ee--ensure)
    (let ((ement-e2ee--backoff-unit 0.5))
      (signal-process ement-e2ee--process 'SIGKILL)
      (should (ement-e2ee-test--wait-for (lambda () (timerp ement-e2ee--restart-timer)) 5))
      ;; ement-connect now: it starts the proxy itself, and only it does.
      (ement-e2ee--ensure)
      (should-not (timerp ement-e2ee--restart-timer))
      (ement-e2ee-test--wait-for #'ignore 1)
      (should (process-live-p ement-e2ee--process))
      (let ((log (ement-e2ee-test--log)))
        (should-not (string-match-p "in use by" log))
        (should (= (cl-count-if (lambda (line) (string-match-p "\\] started " line))
                                (split-string log "\n"))
                   2))))))

(ert-deftest ement-e2ee-test-proxy-started-by-a-timer-during-the-probe ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (let ((probe (symbol-function 'ement-e2ee--probe))
          (fired nil))
      ;; A supervised restart fires while ensure waits for its probe.
      (cl-letf (((symbol-function 'ement-e2ee--probe)
                 (lambda (url &optional timeout)
                   (prog1 (funcall probe url timeout)
                     (unless fired
                       (setq fired t)
                       (ement-e2ee--restart-supervised))))))
        (ement-e2ee--ensure))
      (should fired)
      (should (process-live-p ement-e2ee--process))
      (should (process-get ement-e2ee--process 'ready))
      (let ((log (ement-e2ee-test--log)))
        (should-not (string-match-p "in use by" log))
        (should (= (cl-count-if (lambda (line) (string-match-p "\\] started " line))
                                (split-string log "\n"))
                   1))))))

(ert-deftest ement-e2ee-test-proxy-outlives-its-log-buffer ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore config port)
    (let ((url (ement-e2ee--ensure))
          (process ement-e2ee--process))
      ;; What `ement-disconnect' does to every ement buffer, whatever
      ;; sessions remain: the proxy keeps running.
      (ement-kill-buffers)
      (should (get-buffer ement-e2ee--log-buffer-name))
      (kill-buffer ement-e2ee--log-buffer-name)
      (ement-e2ee-test--wait-for #'ignore 1)
      (should (process-live-p process))
      (should (eq ement-e2ee--process process))
      (should (eq (car (ement-e2ee--probe url)) 'proxy))
      ;; The log starts again where it left off.
      (ement-e2ee-stop)
      (should (ement-e2ee-test--wait-for (lambda () (not (process-live-p process))) 10))
      (ement-e2ee--drain process)
      (should (string-match-p "terminated; shutting down" (ement-e2ee-test--log))))))

(ert-deftest ement-e2ee-test-proxy-supervision-gives-up ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore port)
    (ement-e2ee--ensure)
    (let (warning)
      (cl-letf (((symbol-function 'display-warning)
                 (lambda (_type message &rest _) (setq warning message))))
        ;; The config breaks, then the proxy dies: every restart fails.
        (with-temp-buffer
          (insert-file-contents config)
          (goto-char (point-max))
          (insert "store_passphrase_command = \"exit 3\"\n")
          (write-region nil nil config))
        (signal-process ement-e2ee--process 'SIGKILL)
        (should (ement-e2ee-test--wait-for (lambda () warning) 30)))
      (should (string-match-p "failed to start 4 times" warning))
      (should (string-match-p "store_passphrase_command failed" warning))
      (should-not ement-e2ee--process)
      (should-not (timerp ement-e2ee--restart-timer)))))

(ert-deftest ement-e2ee-test-proxy-start-up-failure-is-reported ()
  (ement-e2ee-test--with-proxy config port "store_passphrase_command = \"exit 3\""
    (ignore config port)
    (let ((error (should-error (ement-e2ee--ensure) :type 'user-error)))
      (should (string-match-p "exited at start-up" (cadr error)))
      (should (string-match-p "store_passphrase_command failed" (cadr error))))
    ;; Not supervised before it ever answered: nothing restarts it.
    (should-not ement-e2ee--process)
    (should-not (timerp ement-e2ee--restart-timer))))

(ert-deftest ement-e2ee-test-proxy-downgrade-is-named ()
  (ement-e2ee-test--with-proxy config port nil
    (ignore port)
    (let ((store (expand-file-name "store" (file-name-directory config))))
      (make-directory store t)
      (with-temp-file (expand-file-name ".version" store)
        (insert "99.0.0\n")))
    (let ((error (should-error (ement-e2ee--ensure) :type 'user-error)))
      (should (string-match-p "newer than this" (cadr error)))
      (should (string-match-p "install ≥ 99.0.0" (cadr error))))))

(ert-deftest ement-e2ee-test-proxy-port-taken-by-something-else ()
  (ement-e2ee-test--with-temp-dir dir
    (ement-e2ee-test--with-state
      (skip-unless ement-e2ee-test--program)
      (let* ((server (make-network-process
                      :name "ement-e2ee-test-server" :server t :host "127.0.0.1" :service t
                      :family 'ipv4 :noquery t
                      :filter (lambda (connection _)
                                (process-send-string
                                 connection
                                 "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
                                (process-send-eof connection))))
             (port (process-contact server :service))
             (ement-e2ee-program ement-e2ee-test--program)
             (ement-e2ee-config-file (ement-e2ee-test--write-config dir port))
             (ement-e2ee-binary-version (ement-e2ee--binary-version ement-e2ee-test--program)))
        (unwind-protect
            (should (string-match-p "in use by something else"
                                    (cadr (should-error (ement-e2ee--ensure)
                                                        :type 'user-error))))
          (delete-process server))
        (should-not ement-e2ee--process)))))

(provide 'ement-e2ee-test)

;;; ement-e2ee-test.el ends here
