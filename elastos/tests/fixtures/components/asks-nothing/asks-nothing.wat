(component
  (import "elastos:bus/types@1.0.0" (instance $types
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "internal" string)))
    (export "bus-error" (type (eq $error)))))
  (alias export $types "bus-error" (type $bus-error))
  (core module $m
    (memory (export "memory") 1)
    (func (export "run") (result i32) (i32.const 0)))
  (core instance $i (instantiate $m))
  (func $run (result (result (error $bus-error)))
    (canon lift (core func $i "run") (memory $i "memory")))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))
