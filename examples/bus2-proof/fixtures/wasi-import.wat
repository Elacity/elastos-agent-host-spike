;; A wasi:* import next to a bus import: refused (wasi_import).
(component
  (import "elastos:bus/runtime@2.0.0" (instance))
  (import "wasi:cli/environment@0.2.0" (instance)))
