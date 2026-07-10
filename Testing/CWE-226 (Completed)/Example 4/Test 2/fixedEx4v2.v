module secret_fifo_secure (
    input  wire        clk,
    input  wire        rst,

    // Functional interface
    input  wire        push,
    input  wire        pop,
    input  wire [63:0] secret_in,
    output reg  [63:0] secret_out,
    output reg         empty,
    output reg         full,

    // Security / privilege interface
    input  wire        priv_ok,        // 1 = caller is privileged
    input  wire        domain_switch,  // 1 = context switch between trust domains
    input  wire        lock_set,       // 1 = configuration locked (fuse)
    input  wire        glitch_detect,  // 1 = clock/voltage glitch detected
    input  wire        debug_mode      // debug active (must NOT bypass locks)
);

    // Secret storage
    reg [63:0] secret [0:3];

    // Pointers and count (bounded)
    reg [1:0] head, tail;
    reg [1:0] count;        // 0..3 only
    reg       error_state;  // defensive error state

    wire ops_allowed = priv_ok && lock_set && !glitch_detect && !error_state;

    integer i;

    // Sequential logic
    always @(posedge clk) begin
        if (rst) begin
            // CWE-226: scrub secrets on reset
            for (i = 0; i < 4; i = i + 1)
                secret[i] <= 64'b0;

            head        <= 0;
            tail        <= 0;
            count       <= 0;
            secret_out  <= 64'b0;
            error_state <= 1'b0;
        end else begin
            // CWE-1247: glitch forces safe error state
            if (glitch_detect) begin
                error_state <= 1'b1;
                secret_out  <= 64'b0;
            end

            // CWE-1189: scrub on domain context switch
            if (domain_switch && ops_allowed) begin
                for (i = 0; i < 4; i = i + 1)
                    secret[i] <= 64'b0;
                head   <= 0;
                tail   <= 0;
                count  <= 0;
                secret_out <= 64'b0;
            end

            // Normal operations only when secure
            if (ops_allowed) begin
                // CWE-1260: strictly bounded count, deny on conflict
                if (push && !full) begin
                    secret[tail] <= secret_in;
                    tail         <= tail + 1'b1;
                    count        <= count + 1'b1;
                end

                if (pop && !empty) begin
                    secret_out <= secret[head];
                    head       <= head + 1'b1;
                    count      <= count - 1'b1;
                end
            end else begin
                // CWE-1256 / 1262: default deny for unprivileged/unlocked/error/glitch
                if (push || pop) begin
                    secret_out <= 64'b0;
                end
            end

            // CWE-1234: debug_mode cannot override lock
            if (debug_mode && !lock_set) begin
                // In debug before lock, force zero output
                secret_out <= 64'b0;
            end
        end
    end

    // Combinational status
    always @(*) begin
        empty = (count == 0);
        full  = (count == 3);
    end

endmodule
