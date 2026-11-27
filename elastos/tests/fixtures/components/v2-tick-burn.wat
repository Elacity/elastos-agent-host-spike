;; Cheap burn, then either a 1 ms sleep or a sleep that is cancelled and dropped.
;; park-mode 0 awaits. park-mode 1 cancels. The guest clock steps on its own.
(component
  (import "elastos:bus/clock@2.0.0" (instance $clock
    (export "now-ms" (func (result u64)))
    (export "sleep-until-ms" (func async (param "deadline" u64)))))
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
  (alias export $clock "now-ms" (func $now-f))
  (alias export $clock "sleep-until-ms" (func $sleep-f))
  (alias export $types "bus-error" (type $error))
  (alias export $types "event" (type $event))
  (type $events (stream $event))
  (type $reply (result (error $error)))
  (type $run (func async (param "events" $events) (result $reply)))
  (core module $shim
    (type $sleep (func (param i64) (result i32)))
    (type $now (func (result i64)))
    (type $new (func (result i32)))
    (type $join (func (param i32 i32)))
    (type $cancel (func (param i32) (result i32)))
    (type $drop (func (param i32)))
    (table (export "table") 6 funcref)
    (func (export "sleep") (type $sleep)
      local.get 0 i32.const 0 call_indirect (type $sleep))
    (func (export "now") (type $now)
      i32.const 1 call_indirect (type $now))
    (func (export "new") (type $new)
      i32.const 2 call_indirect (type $new))
    (func (export "join") (type $join)
      local.get 0 local.get 1 i32.const 3 call_indirect (type $join))
    (func (export "cancel") (type $cancel)
      local.get 0 i32.const 4 call_indirect (type $cancel))
    (func (export "drop") (type $drop)
      local.get 0 i32.const 5 call_indirect (type $drop)))
  (core instance $shim-i (instantiate $shim))
  (alias core export $shim-i "sleep" (core func $shim-sleep))
  (alias core export $shim-i "now" (core func $shim-now))
  (alias core export $shim-i "new" (core func $shim-new))
  (alias core export $shim-i "join" (core func $shim-join))
  (alias core export $shim-i "cancel" (core func $shim-cancel))
  (alias core export $shim-i "drop" (core func $shim-drop))
  (core instance $host
    (export "sleep" (func $shim-sleep))
    (export "now" (func $shim-now))
    (export "new" (func $shim-new))
    (export "join" (func $shim-join))
    (export "cancel" (func $shim-cancel))
    (export "drop" (func $shim-drop)))
  (core module $guest
    (import "host" "sleep" (func $sleep (param i64) (result i32)))
    (import "host" "now" (func $now (result i64)))
    (import "host" "new" (func $new (result i32)))
    (import "host" "join" (func $join (param i32 i32)))
    (import "host" "cancel" (func $cancel-sub (param i32) (result i32)))
    (import "host" "drop" (func $drop-sub (param i32)))
    (memory (export "memory") 1)
    (global $at (mut i64) (i64.const 0))
    (global $mode (mut i32) (i32.const 0)) ;; park-mode
    (global $set (mut i32) (i32.const 0))
    (func $burn
      (local $start i64)
      i32.const 0 i32.const 0 i32.const 65536 memory.fill
      call $now local.set $start
      (loop $again
        call $now local.get $start i64.sub i64.const 40 i64.lt_s
        br_if $again))
    (func $arm (param $step i64) (result i32)
      global.get $at local.get $step i64.add global.set $at
      global.get $at call $sleep)
    (func $park (param $handle i32) (result i32)
      local.get $handle global.get $set call $join
      global.get $set i32.const 4 i32.shl i32.const 2 i32.or)
    (func $await-loop (result i32)
      (local $code i32)
      (loop $again
        call $burn
        i64.const 1 call $arm local.tee $code
        i32.const 15 i32.and i32.const 2 i32.eq
        br_if $again)
      local.get $code i32.const 4 i32.shr_u local.tee $code
      i32.eqz if unreachable end
      local.get $code call $park)
    (func $cancel-loop (result i32)
      (local $code i32) (local $sub i32)
      (loop $again
        call $burn
        i64.const 1000 call $arm local.set $code
        local.get $code i32.const 15 i32.and i32.const 2 i32.ne
        if
          local.get $code i32.const 4 i32.shr_u local.tee $sub
          i32.eqz if unreachable end
          local.get $sub call $cancel-sub drop
          local.get $sub call $drop-sub
        end
        br $again)
      i32.const 0)
    (func (export "run") (param $stream i32) (result i32)
      local.get $stream drop
      call $new global.set $set
      global.get $mode i32.eqz
      if call $await-loop return end
      call $cancel-loop)
    (func (export "callback") (param $event i32) (param $handle i32) (param $result i32) (result i32)
      local.get $event drop
      local.get $handle drop
      local.get $result i32.const 15 i32.and i32.const 2 i32.ne
      if unreachable end
      call $await-loop))
  (core instance $guest-i (instantiate $guest (with "host" (instance $host))))
  (alias core export $guest-i "memory" (core memory $memory))
  (core func $sleep (canon lower (func $sleep-f) async))
  (core func $now (canon lower (func $now-f)))
  (core func $new (canon waitable-set.new))
  (core func $join (canon waitable.join))
  (core func $cancel (canon subtask.cancel))
  (core func $drop (canon subtask.drop))
  (core module $fix
    (import "" "0" (func $sleep (param i64) (result i32)))
    (import "" "1" (func $now (result i64)))
    (import "" "2" (func $new (result i32)))
    (import "" "3" (func $join (param i32 i32)))
    (import "" "4" (func $cancel (param i32) (result i32)))
    (import "" "5" (func $drop (param i32)))
    (import "" "$imports" (table 6 funcref))
    (elem (i32.const 0) func $sleep $now $new $join $cancel $drop))
  (alias core export $shim-i "table" (core table $table))
  (core instance $fix-args
    (export "0" (func $sleep))
    (export "1" (func $now))
    (export "2" (func $new))
    (export "3" (func $join))
    (export "4" (func $cancel))
    (export "5" (func $drop))
    (export "$imports" (table $table)))
  (core instance $fix-i (instantiate $fix (with "" (instance $fix-args))))
  (alias core export $guest-i "run" (core func $guest-run))
  (alias core export $guest-i "callback" (core func $guest-callback))
  (func $run (type $run) (canon lift (core func $guest-run) (memory $memory) async (callback $guest-callback)))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@2.0.0" (instance $lifecycle)))
