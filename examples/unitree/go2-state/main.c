/** Read one Go2 sample from the reviewed, read-only DDS replay attachment. */
#include <uwrosv2/capability.h>
#include <uwrosv2/clock.h>
#include <uwrosv2/driver.h>
#include <uwrosv2/unitree/go2_low_state.h>

typedef uwrosv2_transfer (*driver_call)(uwrosv2_capability, uwrosv2_input, uwrosv2_output);

static uwrosv2_transfer poll(driver_call operation, uwrosv2_capability driver,
                             uwrosv2_input request, uwrosv2_output reply) {
    for (unsigned attempt = 0; attempt < 4000000; ++attempt) {
        uwrosv2_transfer call = operation(driver, request, reply);
        if (call.status != UWROSV2_AGAIN)
            return call;
    }
    __builtin_trap();
}

static uint64_t deadline(uwrosv2_capability cap, uwrosv2_resource clock) {
    const int64_t window_ns = INT64_C(10000000000);
    uwrosv2_clock_sample sample;
    if (uwrosv2_clock_read(cap, clock, &sample) || !sample.started ||
        sample.kind != UWROSV2_CLOCK_STEADY || sample.now <= 0 ||
        sample.now > INT64_MAX - window_ns)
        __builtin_trap();
    return (uint64_t)(sample.now + window_ns);
}

void _start(void) {
    uwrosv2_capability driver, steady;
    uwrosv2_resource clock;
    if (uwrosv2_capability_open(uwrosv2_string("go2-state", 9), &driver) ||
        uwrosv2_capability_open(uwrosv2_string("steady", 6), &steady) ||
        uwrosv2_clock_create(steady, UWROSV2_CLOCK_STEADY, &clock))
        __builtin_trap();

    /* The replay negotiates 32 response bytes, plus the 16-byte result header. */
    uint8_t reply[48];
    uwrosv2_input empty = uwrosv2_bytes(NULL, 0);
    uwrosv2_output output = uwrosv2_mut_bytes(reply, sizeof reply);
    uwrosv2_transfer call = poll(uwrosv2_driver_connect_record, driver, empty, output);
    if (call.status || call.size != 8 || uwrosv2_read_le64(reply) != 1)
        __builtin_trap();

    uint8_t request[UWROSV2_GO2_READ_BYTES];
    const uint64_t sequence = 1;
    if (!uwrosv2_go2_encode_read(sequence, deadline(steady, clock), request, sizeof request))
        __builtin_trap();
    call = poll(uwrosv2_driver_submit_record, driver, uwrosv2_bytes(request, sizeof request), output);
    if (call.status || call.size != 8 || uwrosv2_read_le64(reply) != sequence)
        __builtin_trap();

    uint8_t pending[8];
    uwrosv2_write_le64(pending, sequence);
    call = poll(uwrosv2_driver_result_record, driver, uwrosv2_bytes(pending, sizeof pending), output);
    uwrosv2_go2_low_state state;
    if (call.status || !uwrosv2_go2_decode_result(reply, call.size, &state) ||
        state.tick != 41347 || state.first_joint_position != 0.125f)
        __builtin_trap();

    call = uwrosv2_driver_disconnect_record(driver, empty, output);
    if (call.status || call.size != 8 || uwrosv2_read_le64(reply) != 1)
        __builtin_trap();
}
