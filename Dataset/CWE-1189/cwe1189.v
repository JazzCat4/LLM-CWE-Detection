// https://cwe.mitre.org/data/definitions/1189.html

// Two masters, (CPU_secure and Peripheral) share a memory block
// Peripheral is supposed to be restricted
// But module does not enforce any access control

module cwe1189 (
    input wire clk,
    input wire reset,

    // Secure CPU master
    input wire cpu_req,
    input wire [7:0] cpu_addr,
    input wire [31:0] cpuwdata,
    input wire cpu_we,
    output reg [31:0] cpu_rdata,

    // Peripheral master (untrusted)
    input wire periph_req,
    input wire [7:0] periph_addr,
    input wire[31:0] periph_wdata,
    input wire periph_we,
    output reg [31:0] periph_rdata
);

// Shared memory resource
reg [31:0] mem [0:255];

// No priv. checks - both master get equal access
reg turn; // 0 for CPU, 1 for Peripheral

always @(posedge clk or posedge reset) begin
    if (reset) turn <= 1'b0;
    else turn <= ~turn; // Alternate access each cycle
end

always @(posedge clk) begin
    if (turn == 1'b0 && cpu_req) begin
        // CPU access
        if (cpu_we) mem[cpu_addr] <= cpu_wdata;
        cpu_rdata <= mem[cpu_addr];
    end else if (turn == 1'b1 && periph_req) begin
        // Peripheral access
        // Pheripheral can read/wire ANY address, including secure regions
        if (periph_we) mem[periph_addr] <= periph_wdata;
        periph_rdata <= mem[periph_addr];
    end
end



endmodule