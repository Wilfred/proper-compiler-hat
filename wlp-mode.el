;;; wlp-mode.el --- a major mode for Wilfred Lisp    -*- lexical-binding: t; -*-

;; Copyright (C) 2020  Wilfred Hughes

;; Author: Wilfred Hughes <me@wilfred.me.uk>
;; Keywords: lisp

;; This program is free software; you can redistribute it and/or modify
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

;; A simple major mode for a crude lisp.

;;; Code:

(defvar wlp-font-lock-keywords
  `(
    (,(regexp-opt '("true" "false"))
     (0 'font-lock-constant-face))

    (,(regexp-opt '("defun" "let" "if" "set!" "while" "do") 'symbols)
     (0 'font-lock-keyword-face))

    (,(rx symbol-start "defun" symbol-end
          (1+ space)
          (group (1+ (or word (syntax symbol)))))
     (1 'font-lock-function-name-face))))

;;;###autoload
(add-to-list 'auto-mode-alist (cons "\\.wlp\\'" 'wlp-mode))

(defvar wlp-mode-syntax-table
  (let ((table (make-syntax-table)))
    ;; Strings
    (modify-syntax-entry ?\" "\"" table)

    ;; Comments
    (modify-syntax-entry ?\; "<" table)

    ;; Newlines end comments.
    (modify-syntax-entry ?\n ">" table)

    ;; Characters that are valid in symbols.
    (modify-syntax-entry ?! "_" table)
    (modify-syntax-entry ?? "_" table)
    (modify-syntax-entry ?= "_" table)
    (modify-syntax-entry ?< "_" table)
    (modify-syntax-entry ?> "_" table)
    (modify-syntax-entry ?+ "_" table)
    (modify-syntax-entry ?- "_" table)
    
    table))

;;;###autoload
(define-derived-mode wlp-mode prog-mode "WLisp"
  "Major mode for editing Wilfred Lisp.

\\{wlp-mode-map}"
  (setq-local font-lock-defaults '(wlp-font-lock-keywords))
  (setq-local comment-start "; ")
  (setq-local indent-line-function #'lisp-indent-line))


(provide 'wlp-mode)
;;; wlp-mode.el ends here
