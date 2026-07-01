

module Ex1 (
    input  wire        clk,
    input  wire        rst_n,

    // JTAG debug interface
    input  wire        dbg_en,       // debug enable (external input)
    input  wire        dbg_wr,       // 1=write, 0=read
    input  wire [3:0]  dbg_addr,     // register address
    input  wire [31:0] dbg_wdata,    // write data
    output reg  [31:0] dbg_rdata,    // read data

    // System status outputs
    output wire [1:0]  privilege_level,
    output wire [31:0] secret_key
);

    // Internal security-sensitive registers
    reg [31:0] secret_key_reg;     // Address 0x0: secret key (highly sensitive)
    reg [1:0]  privilege_reg;      // Address 0x1: privilege level (0=user, 3=root)
    reg [31:0] status_reg;         // Address 0x2: system status

    assign secret_key     = secret_key_reg;
    assign privilege_level = privilege_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            secret_key_reg <= 32'hDEADBEEF;  // Load key after reset
            privilege_reg  <= 2'b00;          // Default: user privilege
            status_reg     <= 32'h0;
            dbg_rdata      <= 32'h0;
        end else if (dbg_en) begin            
            if (dbg_wr) begin
                
                case (dbg_addr)
                    4'h0: secret_key_reg <= dbg_wdata;      
                    4'h1: privilege_reg  <= dbg_wdata[1:0]; 
                    4'h2: status_reg     <= dbg_wdata;
                    default: ;
                endcase
            end else begin
                
                case (dbg_addr)
                    4'h0: dbg_rdata <= secret_key_reg;          
                    4'h1: dbg_rdata <= {30'h0, privilege_reg};
                    4'h2: dbg_rdata <= status_reg;
                    default: dbg_rdata <= 32'hDEAD_DEAD;
                endcase
            end
        end
    end

endmodule

