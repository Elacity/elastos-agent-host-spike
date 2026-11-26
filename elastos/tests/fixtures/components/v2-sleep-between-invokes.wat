;; Four invokes. A 40 ms burn, then the invoke, then a real 1 s sleep.
;; The events read stays pending for the whole run.
(component
  (import "elastos:bus/clock@2.0.0" (instance $clock
    (export "now-ms" (func (result u64)))
    (export "sleep-until-ms" (func async (param "deadline" u64)))))
  (import "elastos:bus/types@2.0.0" (instance $types
    (type $request (record (field "resource" string) (field "operation" string)
      (field "grant" (option string)) (field "params" (list u8))))
    (export "invoke-request" (type (eq $request)))
    (type $status (record (field "status" string) (field "audit" (option string))))
    (export "invoke-status" (type (eq $status)))
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
  (alias export $clock "now-ms" (func $now-f))
  (alias export $clock "sleep-until-ms" (func $sleep-f))
  (alias export $types "invoke-request" (type $request))
  (alias export $types "invoke-status" (type $status))
  (alias export $types "bus-error" (type $error))
  (alias export $types "event" (type $event))
  (type $body (stream u8))
  (type $unit-result (result (error $error)))
  (type $trailer (future $unit-result))
  (type $invoke-result (result (tuple $status $body $trailer) (error $error)))
  (type $invoke (func async (param "request" $request) (param "body" (option $body)) (result $invoke-result)))
  (import "elastos:bus/providers@2.0.0" (instance $providers
    (export "invoke-request" (type (eq $request)))
    (export "invoke-status" (type (eq $status)))
    (export "bus-error" (type (eq $error)))
    (export "invoke" (func (type $invoke)))))
  (alias export $providers "invoke" (func $invoke-f))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $call (func (param i32 i32) (result i32)))
    (type $now (func (result i64)))
    (type $sleep (func (param i64) (result i32)))
    (type $read (func (param i32 i32 i32) (result i32)))
    (type $done (func (param i32 i32 i32 i32)))
    (type $new (func (result i32)))
    (type $join (func (param i32 i32)))
    (table (export "table") 7 funcref)
    (func (export "invoke") (type $call)
      local.get 0 local.get 1 i32.const 0 call_indirect (type $call))
    (func (export "now") (type $now)
      i32.const 1 call_indirect (type $now))
    (func (export "sleep") (type $sleep)
      local.get 0 i32.const 2 call_indirect (type $sleep))
    (func (export "read") (type $read)
      local.get 0 local.get 1 local.get 2 i32.const 3 call_indirect (type $read))
    (func (export "done") (type $done)
      local.get 0 local.get 1 local.get 2 local.get 3 i32.const 4 call_indirect (type $done))
    (func (export "new") (type $new)
      i32.const 5 call_indirect (type $new))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 6 call_indirect (type $join)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "invoke" (core func $shim-invoke))
  (alias core export $shim-i "now" (core func $shim-now))
  (alias core export $shim-i "sleep" (core func $shim-sleep))
  (alias core export $shim-i "read" (core func $shim-read))
  (alias core export $shim-i "done" (core func $shim-done))
  (alias core export $shim-i "new" (core func $shim-new))
  (alias core export $shim-i "join" (core func $shim-join))
  (core instance $host
    (export "invoke" (func $shim-invoke)) (export "now" (func $shim-now))
    (export "sleep" (func $shim-sleep)) (export "read" (func $shim-read))
    (export "done" (func $shim-done)) (export "new" (func $shim-new))
    (export "join" (func $shim-join)))
  (core module $guest
    (import "host" "invoke" (func $invoke (param i32 i32) (result i32)))
    (import "host" "now" (func $now (result i64)))
    (import "host" "sleep" (func $sleep (param i64) (result i32)))
    (import "host" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "host" "done" (func $done (param i32 i32 i32 i32)))
    (import "host" "new" (func $new (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (memory (export "memory") 2)
    (data (i32.const 128) "localhost://Local/note.txt")
    (data (i32.const 192) "read")
    (data (i32.const 208) "{\"max_bytes\":1}")
    (data (i32.const 224) "g")
    (global $heap (mut i32) (i32.const 4096))
    (global $events (mut i32) (i32.const 0))
    (global $set (mut i32) (i32.const 0))
    (global $left (mut i32) (i32.const 4))
    (global $at (mut i64) (i64.const 0))
    (global $phase (mut i32) (i32.const 0))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ptr i32) (local $mask i32) (local $end i32) (local $have i32)
      local.get 2 i32.const 1 i32.sub local.set $mask
      global.get $heap local.get $mask i32.add
      local.get $mask i32.const -1 i32.xor
      i32.and local.set $ptr
      local.get $ptr local.get 3 i32.add local.set $end
      memory.size i32.const 16 i32.shl local.set $have
      local.get $end local.get $have i32.gt_u
      if
        local.get $end local.get $have i32.sub
        i32.const 65535 i32.add
        i32.const 16 i32.shr_u
        memory.grow drop
      end
      local.get $end global.set $heap
      local.get $ptr)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $finish (result i32)
      i32.const 0 i32.const 0 i32.const 0 i32.const 0 call $done
      i32.const 0)
    (func $prepare
      i32.const 64 i32.const 128 i32.store
      i32.const 68 i32.const 26 i32.store
      i32.const 72 i32.const 192 i32.store
      i32.const 76 i32.const 4 i32.store
      i32.const 80 i32.const 1 i32.store
      i32.const 84 i32.const 224 i32.store
      i32.const 88 i32.const 1 i32.store
      i32.const 92 i32.const 208 i32.store
      i32.const 96 i32.const 15 i32.store
      i32.const 100 i32.const 0 i32.store
      i32.const 104 i32.const 0 i32.store)
    (func $burn
      (local $start i64)
      i32.const 0 i32.const 0 i32.const 64 memory.fill
      call $now local.set $start
      (loop $again
        call $now local.get $start i64.sub i64.const 40 i64.lt_s
        br_if $again))
    (func $sleep-1s (result i32)
      (local $code i32)
      global.get $at i64.const 1000 i64.add global.set $at
      global.get $at call $sleep local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $step return end
      i32.const 1 global.set $phase
      local.get $code i32.const 4 i32.shr_u call $park)
    (func $step (result i32)
      (local $code i32)
      global.get $left i32.eqz
      if call $finish return end
      call $burn
      global.get $left i32.const 1 i32.sub global.set $left
      call $prepare
      i32.const 64 i32.const 256 call $invoke local.set $code
      local.get $code i32.const 15 i32.and i32.const 2 i32.eq
      if call $sleep-1s return end
      i32.const 0 global.set $phase
      local.get $code i32.const 4 i32.shr_u call $park)
    (func (export "run") (param $stream i32) (result i32)
      local.get $stream global.set $events
      call $new global.set $set
      global.get $events i32.const 8 i32.const 1 call $read drop
      call $step)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $handle drop
      local.get $event i32.const 1 i32.eq
      if
        local.get $result i32.const 15 i32.and i32.const 2 i32.ne
        if unreachable end
        global.get $phase i32.const 1 i32.eq
        if call $step return end
        call $sleep-1s
        return
      end
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (alias core export $guest-i "realloc" (core func $realloc))
  (core func $invoke (canon lower (func $invoke-f) (memory $memory) (realloc $realloc) string-encoding=utf8 async))
  (core func $now (canon lower (func $now-f)))
  (core func $sleep (canon lower (func $sleep-f) async))
  (core func $read (canon stream.read $events (memory $memory) (realloc $realloc) async))
  (core func $done (canon task.return (result $reply) (memory $memory) string-encoding=utf8))
  (core func $new (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core module $fix
    (import "" "0" (func $invoke (param i32 i32) (result i32)))
    (import "" "1" (func $now (result i64)))
    (import "" "2" (func $sleep (param i64) (result i32)))
    (import "" "3" (func $read (param i32 i32 i32) (result i32)))
    (import "" "4" (func $done (param i32 i32 i32 i32)))
    (import "" "5" (func $new (result i32)))
    (import "" "6" (func $join (param i32 i32)))
    (import "" "$imports" (table 7 funcref))
    (elem (i32.const 0) func $invoke $now $sleep $read $done $new $join))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $invoke)) (export "1" (func $now))
    (export "2" (func $sleep)) (export "3" (func $read))
    (export "4" (func $done)) (export "5" (func $new))
    (export "6" (func $join))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
