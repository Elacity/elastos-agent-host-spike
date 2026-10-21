;; Bus v1 and Bus v2 in one guest: refused (mixed_bus_versions).
(component
  (import "elastos:bus/runtime@1.0.0" (instance))
  (import "elastos:bus/runtime@2.0.0" (instance)))
