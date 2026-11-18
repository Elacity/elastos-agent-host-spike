;; A small Bus v2 guest: read events until the host closes the stream.
(component
  (import "elastos:bus/types@2.0.0" (instance $types
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "conflict" string)
      (case "internal" string)))
    (export "bus-error" (type (eq $error)))
    (type $grant-id string)
    (export "grant-id" (type (eq $grant-id)))
    (type $event (variant (case "stop-requested") (case "user-input" (list u8))
      (case "message" (list u8)) (case "grant-revoked" $grant-id)))
    (export "event" (type (eq $event)))))
  (alias export $types "bus-error" (type $error))
  (alias export $types "event" (type $event))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (table (export "table") 2 funcref)
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 0
      call_indirect (type $read))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 1
      call_indirect (type $done)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "done" (core func $shim-done))
  (core instance $host (export "read" (func $shim-read)) (export "done" (func $shim-done)))
  (core module $guest
    (import "elastos:bus/types@2.0.0" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "elastos:bus/types@2.0.0" "done" (func $done (param i32 i32 i32 i32)))
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $old i32)
      global.get $heap local.tee $old
      local.get 3 i32.add global.set $heap
      local.get $old)
    (func (export "run") (param $events i32)
      (loop $again
        local.get $events i32.const 128 i32.const 1 call $read
        i32.const 15 i32.and i32.eqz br_if $again)
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done))
  (core instance $guest-i (instantiate $guest (with "elastos:bus/types@2.0.0" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $read (canon stream.read $events (memory $memory) (realloc $realloc)))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core module $fix
    (import "" "0" (func $read (param i32 i32 i32) (result i32)))
    (import "" "1" (func $done (param i32 i32 i32 i32)))
    (import "" "$imports" (table 2 funcref))
    (elem (i32.const 0) func $read $done))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args (export "0" (func $read)) (export "1" (func $done)) (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
