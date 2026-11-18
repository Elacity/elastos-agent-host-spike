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
    (type $new (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 4 funcref)
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 0
      call_indirect (type $read))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 1
      call_indirect (type $done))
    (func (export "new") (type $new)
      i32.const 2 call_indirect (type $new))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 3 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new" (core func $shim-new))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host (export "read" (func $shim-read)) (export "done" (func $shim-done))
    (export "new" (func $shim-new)) (export "join" (func $shim-join)))
  (core module $guest
    (import "elastos:bus/types@2.0.0" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "elastos:bus/types@2.0.0" "done" (func $done (param i32 i32 i32 i32)))
    (import "elastos:bus/types@2.0.0" "new" (func $new (result i32)))
    (import "elastos:bus/types@2.0.0" "join" (func $join (param i32 i32)))
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 1024))
    (global $events (mut i32) (i32.const 0))
    (global $set (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $old i32)
      global.get $heap local.tee $old
      local.get 3 i32.add global.set $heap
      local.get $old)
    ;; A blocked async read is resumed by the callback's stream-read event.
    (func $next (result i32)
      (local $code i32)
      (loop $again
        global.get $events i32.const 128 i32.const 1 call $read
        local.tee $code
        i32.const -1 i32.eq
        if
          global.get $events global.get $set call $join
          global.get $set i32.const 4 i32.shl i32.const 2 i32.or return
        end
        local.get $code i32.const 15 i32.and i32.eqz br_if $again)
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func (export "run") (param $stream i32) (result i32)
      local.get $stream global.set $events
      call $new global.set $set
      call $next)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event i32.const 2 i32.eq
      if
        local.get $result i32.const 15 i32.and i32.eqz
        if
          call $next return
        end
        i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
        i32.const 0 return
      end
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or))
  (core instance $guest-i (instantiate $guest (with "elastos:bus/types@2.0.0" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $read (canon stream.read $events (memory $memory) (realloc $realloc) async))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $read (param i32 i32 i32) (result i32)))
    (import "" "1" (func $done (param i32 i32 i32 i32)))
    (import "" "2" (func $new (result i32)))
    (import "" "3" (func $join (param i32 i32)))
    (import "" "$imports" (table 4 funcref))
    (elem (i32.const 0) func $read $done $new $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args (export "0" (func $read)) (export "1" (func $done))
    (export "2" (func $new)) (export "3" (func $join)) (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
