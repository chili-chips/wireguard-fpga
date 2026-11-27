# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# 
# SPDX-License-Identifier: BSD-3-Clause

##==========================================================================
## Description:
##   Constraints
##==========================================================================

############## NET - IOSTANDARD ######################
set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]

#############SPI Configurate Setting##################
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
set_property CONFIG_MODE SPIx4 [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE 50 [current_design]
set_property BITSTREAM.CONFIG.CCLK_TRISTATE TRUE [current_design]
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]

############## clock define###########################
create_clock -period 5.000 [get_ports clk_p]
set_property PACKAGE_PIN R4 [get_ports clk_p]
set_property IOSTANDARD DIFF_SSTL15 [get_ports clk_p]

#################reset setting########################
set_property IOSTANDARD LVCMOS15 [get_ports rst_n]
set_property PACKAGE_PIN T6 [get_ports rst_n]

###################MDIO##############################
set_property PACKAGE_PIN L16 [get_ports e1_mdio]
set_property IOSTANDARD LVCMOS33 [get_ports e1_mdio]
set_property PACKAGE_PIN AB22 [get_ports e2_mdio]
set_property IOSTANDARD LVCMOS33 [get_ports e2_mdio]
set_property PACKAGE_PIN V19 [get_ports e3_mdio]
set_property IOSTANDARD LVCMOS33 [get_ports e3_mdio]
set_property PACKAGE_PIN U20 [get_ports e4_mdio]
set_property IOSTANDARD LVCMOS33 [get_ports e4_mdio]
set_property PULLTYPE PULLUP [get_ports e1_mdc]
set_property SLEW SLOW [get_ports e1_mdio]
set_property PULLTYPE PULLUP [get_ports e1_mdio]
set_property PULLTYPE PULLUP [get_ports e2_mdc]
set_property SLEW SLOW [get_ports e2_mdio]
set_property PULLTYPE PULLUP [get_ports e2_mdio]
set_property PULLTYPE PULLUP [get_ports e3_mdc]
set_property SLEW SLOW [get_ports e3_mdio]
set_property PULLTYPE PULLUP [get_ports e3_mdio]
set_property PULLTYPE PULLUP [get_ports e4_mdc]
set_property SLEW SLOW [get_ports e4_mdio]
set_property PULLTYPE PULLUP [get_ports e4_mdio]

#############LED Setting###########################
set_property PACKAGE_PIN E17 [get_ports {led[0]}]
set_property IOSTANDARD LVCMOS33 [get_ports {led[0]}]

set_property PACKAGE_PIN F16 [get_ports {led[1]}]
set_property IOSTANDARD LVCMOS33 [get_ports {led[1]}]

############## key define############################
set_property PACKAGE_PIN D16 [get_ports {key_in[0]}]
set_property IOSTANDARD LVCMOS33 [get_ports {key_in[0]}]

set_property PACKAGE_PIN E16 [get_ports {key_in[1]}]
set_property IOSTANDARD LVCMOS33 [get_ports {key_in[1]}]

############## usb uart define########################
set_property IOSTANDARD LVCMOS33 [get_ports uart_rx]
set_property PACKAGE_PIN AA15 [get_ports uart_rx]

set_property IOSTANDARD LVCMOS33 [get_ports uart_tx]
set_property PACKAGE_PIN AB15 [get_ports uart_tx]

############## SPI config flash (x1, after configuration; CCLK via STARTUPE2)
set_property IOSTANDARD LVCMOS33 [get_ports qspi_cs]
set_property PACKAGE_PIN T19 [get_ports qspi_cs]
set_property IOSTANDARD LVCMOS33 [get_ports qspi_d0]
set_property PACKAGE_PIN P22 [get_ports qspi_d0]
set_property IOSTANDARD LVCMOS33 [get_ports qspi_d1]
set_property PACKAGE_PIN R22 [get_ports qspi_d1]
set_property IOSTANDARD LVCMOS33 [get_ports qspi_d2]
set_property PACKAGE_PIN P21 [get_ports qspi_d2]
set_property IOSTANDARD LVCMOS33 [get_ports qspi_d3]
set_property PACKAGE_PIN R21 [get_ports qspi_d3]

############## ethernet PORT1 RX define############
create_clock -period 8.000 -name e1_rx_clk [get_ports e1_rxc]
set_property IOSTANDARD LVCMOS33 [get_ports e1_rxc]
set_property PACKAGE_PIN K18 [get_ports e1_rxc]

set_property PACKAGE_PIN J17 [get_ports e1_mdc]
set_property IOSTANDARD LVCMOS33 [get_ports e1_mdc]

set_property IOSTANDARD LVCMOS33 [get_ports e1_rxdv]
set_property PACKAGE_PIN M22 [get_ports e1_rxdv]

set_property IOSTANDARD LVCMOS33 [get_ports e1_rxer]
set_property PACKAGE_PIN N18 [get_ports e1_rxer]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[0]}]
set_property PACKAGE_PIN N22 [get_ports {e1_rxd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[1]}]
set_property PACKAGE_PIN H18 [get_ports {e1_rxd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[2]}]
set_property PACKAGE_PIN H17 [get_ports {e1_rxd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[3]}]
set_property PACKAGE_PIN M21 [get_ports {e1_rxd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[4]}]
set_property PACKAGE_PIN L21 [get_ports {e1_rxd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[5]}]
set_property PACKAGE_PIN N20 [get_ports {e1_rxd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[6]}]
set_property PACKAGE_PIN M20 [get_ports {e1_rxd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_rxd[7]}]
set_property PACKAGE_PIN N19 [get_ports {e1_rxd[7]}]
############## ethernet PORT1 TX define##############
set_property IOSTANDARD LVCMOS33 [get_ports e1_txc]
set_property PACKAGE_PIN K21 [get_ports e1_txc]
# the PHY's TX clock in MII mode (10/100: 2.5/25 MHz); gmii_phy_if selects it
# with a BUFGMUX instead of the 125 MHz GTX clock
create_clock -period 40.000 -name e1_mii_tx_clk [get_ports e1_txc]

set_property IOSTANDARD LVCMOS33 [get_ports e1_gtxc]
set_property PACKAGE_PIN G21 [get_ports e1_gtxc]

set_property IOSTANDARD LVCMOS33 [get_ports e1_txen]
set_property PACKAGE_PIN G22 [get_ports e1_txen]

set_property IOSTANDARD LVCMOS33 [get_ports e1_txer]
set_property PACKAGE_PIN K17 [get_ports e1_txer]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[0]}]
set_property PACKAGE_PIN D22 [get_ports {e1_txd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[1]}]
set_property PACKAGE_PIN H20 [get_ports {e1_txd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[2]}]
set_property PACKAGE_PIN H22 [get_ports {e1_txd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[3]}]
set_property PACKAGE_PIN J22 [get_ports {e1_txd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[4]}]
set_property PACKAGE_PIN K22 [get_ports {e1_txd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[5]}]
set_property PACKAGE_PIN L19 [get_ports {e1_txd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[6]}]
set_property PACKAGE_PIN K19 [get_ports {e1_txd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e1_txd[7]}]
set_property PACKAGE_PIN L20 [get_ports {e1_txd[7]}]

set_property IOSTANDARD LVCMOS33 [get_ports e1_reset]
set_property PACKAGE_PIN G20 [get_ports e1_reset]

############## ethernet PORT2 RX define#################
create_clock -period 8.000 -name e2_rx_clk [get_ports e2_rxc]
set_property IOSTANDARD LVCMOS33 [get_ports e2_rxc]
set_property PACKAGE_PIN J20 [get_ports e2_rxc]

set_property PACKAGE_PIN AB21 [get_ports e2_mdc]
set_property IOSTANDARD LVCMOS33 [get_ports e2_mdc]

set_property IOSTANDARD LVCMOS33 [get_ports e2_rxdv]
set_property PACKAGE_PIN L13 [get_ports e2_rxdv]

set_property IOSTANDARD LVCMOS33 [get_ports e2_rxer]
set_property PACKAGE_PIN G13 [get_ports e2_rxer]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[0]}]
set_property PACKAGE_PIN M13 [get_ports {e2_rxd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[1]}]
set_property PACKAGE_PIN K14 [get_ports {e2_rxd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[2]}]
set_property PACKAGE_PIN K13 [get_ports {e2_rxd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[3]}]
set_property PACKAGE_PIN J14 [get_ports {e2_rxd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[4]}]
set_property PACKAGE_PIN H14 [get_ports {e2_rxd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[5]}]
set_property PACKAGE_PIN H15 [get_ports {e2_rxd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[6]}]
set_property PACKAGE_PIN J15 [get_ports {e2_rxd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_rxd[7]}]
set_property PACKAGE_PIN H13 [get_ports {e2_rxd[7]}]
############## ethernet PORT2 TX define##################
set_property IOSTANDARD LVCMOS33 [get_ports e2_txc]
set_property PACKAGE_PIN T14 [get_ports e2_txc]
# the PHY's TX clock in MII mode (10/100: 2.5/25 MHz); gmii_phy_if selects it
# with a BUFGMUX instead of the 125 MHz GTX clock
create_clock -period 40.000 -name e2_mii_tx_clk [get_ports e2_txc]

set_property IOSTANDARD LVCMOS33 [get_ports e2_gtxc]
set_property PACKAGE_PIN M16 [get_ports e2_gtxc]

set_property IOSTANDARD LVCMOS33 [get_ports e2_txen]
set_property PACKAGE_PIN M15 [get_ports e2_txen]

set_property IOSTANDARD LVCMOS33 [get_ports e2_txer]
set_property PACKAGE_PIN T15 [get_ports e2_txer]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[0]}]
set_property PACKAGE_PIN L15 [get_ports {e2_txd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[1]}]
set_property PACKAGE_PIN K16 [get_ports {e2_txd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[2]}]
set_property PACKAGE_PIN W15 [get_ports {e2_txd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[3]}]
set_property PACKAGE_PIN W16 [get_ports {e2_txd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[4]}]
set_property PACKAGE_PIN V17 [get_ports {e2_txd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[5]}]
set_property PACKAGE_PIN W17 [get_ports {e2_txd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[6]}]
set_property PACKAGE_PIN U15 [get_ports {e2_txd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e2_txd[7]}]
set_property PACKAGE_PIN V15 [get_ports {e2_txd[7]}]

set_property IOSTANDARD LVCMOS33 [get_ports e2_reset]
set_property PACKAGE_PIN L14 [get_ports e2_reset]

############## ethernet PORT3 RX define##################
create_clock -period 8.000 -name e3_rx_clk [get_ports e3_rxc]
set_property IOSTANDARD LVCMOS33 [get_ports e3_rxc]
set_property PACKAGE_PIN V13 [get_ports e3_rxc]

set_property PACKAGE_PIN V20 [get_ports e3_mdc]
set_property IOSTANDARD LVCMOS33 [get_ports e3_mdc]

set_property IOSTANDARD LVCMOS33 [get_ports e3_rxdv]
set_property PACKAGE_PIN AA20 [get_ports e3_rxdv]

set_property IOSTANDARD LVCMOS33 [get_ports e3_rxer]
set_property PACKAGE_PIN U21 [get_ports e3_rxer]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[0]}]
set_property PACKAGE_PIN AB20 [get_ports {e3_rxd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[1]}]
set_property PACKAGE_PIN AA19 [get_ports {e3_rxd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[2]}]
set_property PACKAGE_PIN AA18 [get_ports {e3_rxd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[3]}]
set_property PACKAGE_PIN AB18 [get_ports {e3_rxd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[4]}]
set_property PACKAGE_PIN Y17 [get_ports {e3_rxd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[5]}]
set_property PACKAGE_PIN W22 [get_ports {e3_rxd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[6]}]
set_property PACKAGE_PIN W21 [get_ports {e3_rxd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_rxd[7]}]
set_property PACKAGE_PIN T21 [get_ports {e3_rxd[7]}]
############## ethernet PORT3 TX define##################
set_property IOSTANDARD LVCMOS33 [get_ports e3_txc]
set_property PACKAGE_PIN V10 [get_ports e3_txc]
# the PHY's TX clock in MII mode (10/100: 2.5/25 MHz); gmii_phy_if selects it
# with a BUFGMUX instead of the 125 MHz GTX clock
create_clock -period 40.000 -name e3_mii_tx_clk [get_ports e3_txc]

set_property IOSTANDARD LVCMOS33 [get_ports e3_gtxc]
set_property PACKAGE_PIN AA21 [get_ports e3_gtxc]

set_property IOSTANDARD LVCMOS33 [get_ports e3_txen]
set_property PACKAGE_PIN V14 [get_ports e3_txen]

set_property IOSTANDARD LVCMOS33 [get_ports e3_txer]
set_property PACKAGE_PIN AA9 [get_ports e3_txer]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[0]}]
set_property PACKAGE_PIN W11 [get_ports {e3_txd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[1]}]
set_property PACKAGE_PIN W12 [get_ports {e3_txd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[2]}]
set_property PACKAGE_PIN Y11 [get_ports {e3_txd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[3]}]
set_property PACKAGE_PIN Y12 [get_ports {e3_txd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[4]}]
set_property PACKAGE_PIN W10 [get_ports {e3_txd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[5]}]
set_property PACKAGE_PIN AA11 [get_ports {e3_txd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[6]}]
set_property PACKAGE_PIN AA10 [get_ports {e3_txd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e3_txd[7]}]
set_property PACKAGE_PIN AB10 [get_ports {e3_txd[7]}]

set_property IOSTANDARD LVCMOS33 [get_ports e3_reset]
set_property PACKAGE_PIN T20 [get_ports e3_reset]

############## ethernet PORT4 RX define##################
create_clock -period 8.000 -name e4_rx_clk [get_ports e4_rxc]
set_property IOSTANDARD LVCMOS33 [get_ports e4_rxc]
set_property PACKAGE_PIN Y18 [get_ports e4_rxc]

set_property PACKAGE_PIN V18 [get_ports e4_mdc]
set_property IOSTANDARD LVCMOS33 [get_ports e4_mdc]

set_property IOSTANDARD LVCMOS33 [get_ports e4_rxdv]
set_property PACKAGE_PIN W20 [get_ports e4_rxdv]

set_property IOSTANDARD LVCMOS33 [get_ports e4_rxer]
set_property PACKAGE_PIN N13 [get_ports e4_rxer]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[0]}]
set_property PACKAGE_PIN W19 [get_ports {e4_rxd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[1]}]
set_property PACKAGE_PIN Y19 [get_ports {e4_rxd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[2]}]
set_property PACKAGE_PIN V22 [get_ports {e4_rxd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[3]}]
set_property PACKAGE_PIN U22 [get_ports {e4_rxd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[4]}]
set_property PACKAGE_PIN T18 [get_ports {e4_rxd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[5]}]
set_property PACKAGE_PIN R18 [get_ports {e4_rxd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[6]}]
set_property PACKAGE_PIN R14 [get_ports {e4_rxd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_rxd[7]}]
set_property PACKAGE_PIN P14 [get_ports {e4_rxd[7]}]
############## ethernet PORT4 TX define##################
set_property IOSTANDARD LVCMOS33 [get_ports e4_txc]
set_property PACKAGE_PIN U16 [get_ports e4_txc]
# the PHY's TX clock in MII mode (10/100: 2.5/25 MHz); gmii_phy_if selects it
# with a BUFGMUX instead of the 125 MHz GTX clock
create_clock -period 40.000 -name e4_mii_tx_clk [get_ports e4_txc]

set_property IOSTANDARD LVCMOS33 [get_ports e4_gtxc]
set_property PACKAGE_PIN P20 [get_ports e4_gtxc]

set_property IOSTANDARD LVCMOS33 [get_ports e4_txen]
set_property PACKAGE_PIN P16 [get_ports e4_txen]

set_property IOSTANDARD LVCMOS33 [get_ports e4_txer]
set_property PACKAGE_PIN R19 [get_ports e4_txer]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[0]}]
set_property PACKAGE_PIN R17 [get_ports {e4_txd[0]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[1]}]
set_property PACKAGE_PIN P15 [get_ports {e4_txd[1]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[2]}]
set_property PACKAGE_PIN N17 [get_ports {e4_txd[2]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[3]}]
set_property PACKAGE_PIN P17 [get_ports {e4_txd[3]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[4]}]
set_property PACKAGE_PIN T16 [get_ports {e4_txd[4]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[5]}]
set_property PACKAGE_PIN U17 [get_ports {e4_txd[5]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[6]}]
set_property PACKAGE_PIN U18 [get_ports {e4_txd[6]}]

set_property IOSTANDARD LVCMOS33 [get_ports {e4_txd[7]}]
set_property PACKAGE_PIN P19 [get_ports {e4_txd[7]}]

set_property IOSTANDARD LVCMOS33 [get_ports e4_reset]
set_property PACKAGE_PIN R16 [get_ports e4_reset]

### Clocks Routing ###

# the PLL clocks by their output pins, not by their derived names (TIMING-28)
set sys_clk [get_clocks -of_objects [get_pins u_clk_rst_gen/u_sys_pll/sys_pll/CLKOUT0]]
set eth_clk [get_clocks -of_objects [get_pins u_clk_rst_gen/u_eth_pll/eth_pll/CLKOUT0]]
set_false_path -from $sys_clk -to [get_clocks e1_rx_clk]
set_false_path -from [get_clocks e1_rx_clk] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e2_rx_clk]
set_false_path -from [get_clocks e2_rx_clk] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e3_rx_clk]
set_false_path -from [get_clocks e3_rx_clk] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e4_rx_clk]
set_false_path -from [get_clocks e4_rx_clk] -to $sys_clk
set_false_path -from $sys_clk -to $eth_clk
set_false_path -from $eth_clk -to $sys_clk
# TX clock of each port: gmii_phy_if's BUFGMUX passes the 125 MHz GTX clock
# (I0) or, in MII mode, the PHY's TX clock (I1). One clock per mux input on its
# output, never both at once (physically exclusive); the MII one is
# asynchronous to all others, and report_cdc checks its crossings
create_generated_clock -name e1_tx_gtx -divide_by 1 -source [get_pins u_eth_1/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I0] [get_pins u_eth_1/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
create_generated_clock -name e1_tx_mii -divide_by 1 -add -master_clock e1_mii_tx_clk \
  -source [get_pins u_eth_1/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I1] [get_pins u_eth_1/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
set_clock_groups -physically_exclusive -group [get_clocks e1_tx_gtx] -group [get_clocks e1_tx_mii]
set_clock_groups -asynchronous -group [get_clocks {e1_mii_tx_clk e1_tx_mii}]
create_generated_clock -name e2_tx_gtx -divide_by 1 -source [get_pins u_eth_2/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I0] [get_pins u_eth_2/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
create_generated_clock -name e2_tx_mii -divide_by 1 -add -master_clock e2_mii_tx_clk \
  -source [get_pins u_eth_2/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I1] [get_pins u_eth_2/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
set_clock_groups -physically_exclusive -group [get_clocks e2_tx_gtx] -group [get_clocks e2_tx_mii]
set_clock_groups -asynchronous -group [get_clocks {e2_mii_tx_clk e2_tx_mii}]
create_generated_clock -name e3_tx_gtx -divide_by 1 -source [get_pins u_eth_3/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I0] [get_pins u_eth_3/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
create_generated_clock -name e3_tx_mii -divide_by 1 -add -master_clock e3_mii_tx_clk \
  -source [get_pins u_eth_3/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I1] [get_pins u_eth_3/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
set_clock_groups -physically_exclusive -group [get_clocks e3_tx_gtx] -group [get_clocks e3_tx_mii]
set_clock_groups -asynchronous -group [get_clocks {e3_mii_tx_clk e3_tx_mii}]
create_generated_clock -name e4_tx_gtx -divide_by 1 -source [get_pins u_eth_4/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I0] [get_pins u_eth_4/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
create_generated_clock -name e4_tx_mii -divide_by 1 -add -master_clock e4_mii_tx_clk \
  -source [get_pins u_eth_4/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/I1] [get_pins u_eth_4/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/gmii_bufgmux_inst/O]
set_clock_groups -physically_exclusive -group [get_clocks e4_tx_gtx] -group [get_clocks e4_tx_mii]
set_clock_groups -asynchronous -group [get_clocks {e4_mii_tx_clk e4_tx_mii}]
# the TX FIFOs cross between sys_pll_out and the GTX side, as eth_pll_out does
set_false_path -from $sys_clk -to [get_clocks e1_tx_gtx]
set_false_path -from [get_clocks e1_tx_gtx] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e2_tx_gtx]
set_false_path -from [get_clocks e2_tx_gtx] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e3_tx_gtx]
set_false_path -from [get_clocks e3_tx_gtx] -to $sys_clk
set_false_path -from $sys_clk -to [get_clocks e4_tx_gtx]
set_false_path -from [get_clocks e4_tx_gtx] -to $sys_clk

### Synchronizers (as Alex Forencich's axis_async_fifo, eth_mac_1g_gmii and gmii_phy_if .tcl) ###
# the input of a synchronizer is not a timing path; ASYNC_REG is in the RTL
set_false_path -to [get_pins -filter {REF_PIN_NAME == PRE} -of_objects [get_cells -hier -filter {NAME =~ */gmii_phy_if_inst/*_rst_reg_reg[*]}]]
set_false_path -to [get_pins -filter {REF_PIN_NAME == D} -of_objects [get_cells -hier -filter {NAME =~ */eth_mac_1g_gmii_inst/*_mii_select_sync_reg[0]}]]
set_false_path -to [get_pins -filter {REF_PIN_NAME == D} -of_objects [get_cells -hier -filter {NAME =~ */eth_mac_1g_gmii_inst/rx_prescale_sync_reg[0]}]]
# async FIFOs: the gray read pointer, and the frame commit pointer with its
# update toggle, must cross within one 8 ns period; set_bus_skew holds under
# the clock false paths above
set_bus_skew -from [get_cells {u_eth_1/eth/rx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_1/eth/rx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_1/eth/rx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_1/eth/rx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_1/eth/rx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_1/eth/rx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_1/eth/rx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_1/eth/tx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_1/eth/tx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_1/eth/tx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_1/eth/tx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_1/eth/tx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_1/eth/tx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_1/eth/tx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_2/eth/rx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_2/eth/rx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_2/eth/rx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_2/eth/rx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_2/eth/rx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_2/eth/rx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_2/eth/rx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_2/eth/tx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_2/eth/tx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_2/eth/tx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_2/eth/tx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_2/eth/tx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_2/eth/tx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_2/eth/tx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_3/eth/rx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_3/eth/rx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_3/eth/rx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_3/eth/rx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_3/eth/rx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_3/eth/rx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_3/eth/rx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_3/eth/tx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_3/eth/tx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_3/eth/tx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_3/eth/tx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_3/eth/tx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_3/eth/tx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_3/eth/tx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_4/eth/rx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_4/eth/rx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_4/eth/rx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_4/eth/rx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_4/eth/rx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_4/eth/rx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_4/eth/rx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000
set_bus_skew -from [get_cells {u_eth_4/eth/tx_fifo/fifo_inst/rd_ptr_reg_reg[*] u_eth_4/eth/tx_fifo/fifo_inst/rd_ptr_gray_reg_reg[*]}] -to [get_cells u_eth_4/eth/tx_fifo/fifo_inst/rd_ptr_gray_sync1_reg_reg[*]] 8.000
set_bus_skew -from [get_cells {u_eth_4/eth/tx_fifo/fifo_inst/wr_ptr_sync_commit_reg_reg[*] u_eth_4/eth/tx_fifo/fifo_inst/wr_ptr_update_reg_reg}] -to [get_cells {u_eth_4/eth/tx_fifo/fifo_inst/wr_ptr_commit_sync_reg_reg[*] u_eth_4/eth/tx_fifo/fifo_inst/wr_ptr_update_sync1_reg_reg}] 8.000

### Input/Output Delay ###
# RTL8211E GMII (datasheet Rev 1.5, GMII timing): RXD/RXDV/RXER valid from 2.5 ns
# before to 0.5 ns after RXC rises; TXD/TXEN/TXER need 2.0 ns setup and 0 ns hold
# to GTXCLK. At 125 MHz: input delay max 8.0 - 2.5 = 5.5, min 0.5; output delay
# max 2.0, min 0. In MII mode (10/100) the PHY samples on its own TXC (IEEE 802.3
# 22.3.1: TXD changes 0 to 25 ns after TXC rises): max 40 - 25 = 15, min 0.
# Board traces are taken as matched. The forwarded clock comes from the ODDR in
# ssio_sdr_out, inverted (D1 = 0, D2 = 1): the PHY samples in mid-bit
create_generated_clock -name e1_gtx_clk -invert -divide_by 1 -add -master_clock e1_tx_gtx -source [get_pins u_eth_1/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/tx_ssio_sdr_inst/clk_oddr_inst/C] [get_ports e1_gtxc]
set_input_delay -clock e1_rx_clk -max 5.5 [get_ports {e1_rxd[*] e1_rxdv e1_rxer}]
set_input_delay -clock e1_rx_clk -min 0.5 [get_ports {e1_rxd[*] e1_rxdv e1_rxer}]
set_output_delay -clock e1_gtx_clk -max 2.0 [get_ports {e1_txd[*] e1_txen e1_txer}]
set_output_delay -clock e1_gtx_clk -min 0.0 [get_ports {e1_txd[*] e1_txen e1_txer}]
set_output_delay -clock e1_mii_tx_clk -max 15.0 -add_delay [get_ports {e1_txd[*] e1_txen e1_txer}]
set_output_delay -clock e1_mii_tx_clk -min 0.0 -add_delay [get_ports {e1_txd[*] e1_txen e1_txer}]
create_generated_clock -name e2_gtx_clk -invert -divide_by 1 -add -master_clock e2_tx_gtx -source [get_pins u_eth_2/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/tx_ssio_sdr_inst/clk_oddr_inst/C] [get_ports e2_gtxc]
set_input_delay -clock e2_rx_clk -max 5.5 [get_ports {e2_rxd[*] e2_rxdv e2_rxer}]
set_input_delay -clock e2_rx_clk -min 0.5 [get_ports {e2_rxd[*] e2_rxdv e2_rxer}]
set_output_delay -clock e2_gtx_clk -max 2.0 [get_ports {e2_txd[*] e2_txen e2_txer}]
set_output_delay -clock e2_gtx_clk -min 0.0 [get_ports {e2_txd[*] e2_txen e2_txer}]
set_output_delay -clock e2_mii_tx_clk -max 15.0 -add_delay [get_ports {e2_txd[*] e2_txen e2_txer}]
set_output_delay -clock e2_mii_tx_clk -min 0.0 -add_delay [get_ports {e2_txd[*] e2_txen e2_txer}]
create_generated_clock -name e3_gtx_clk -invert -divide_by 1 -add -master_clock e3_tx_gtx -source [get_pins u_eth_3/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/tx_ssio_sdr_inst/clk_oddr_inst/C] [get_ports e3_gtxc]
set_input_delay -clock e3_rx_clk -max 5.5 [get_ports {e3_rxd[*] e3_rxdv e3_rxer}]
set_input_delay -clock e3_rx_clk -min 0.5 [get_ports {e3_rxd[*] e3_rxdv e3_rxer}]
set_output_delay -clock e3_gtx_clk -max 2.0 [get_ports {e3_txd[*] e3_txen e3_txer}]
set_output_delay -clock e3_gtx_clk -min 0.0 [get_ports {e3_txd[*] e3_txen e3_txer}]
set_output_delay -clock e3_mii_tx_clk -max 15.0 -add_delay [get_ports {e3_txd[*] e3_txen e3_txer}]
set_output_delay -clock e3_mii_tx_clk -min 0.0 -add_delay [get_ports {e3_txd[*] e3_txen e3_txer}]
create_generated_clock -name e4_gtx_clk -invert -divide_by 1 -add -master_clock e4_tx_gtx -source [get_pins u_eth_4/eth/eth_mac_1g_gmii_inst/gmii_phy_if_inst/tx_ssio_sdr_inst/clk_oddr_inst/C] [get_ports e4_gtxc]
set_input_delay -clock e4_rx_clk -max 5.5 [get_ports {e4_rxd[*] e4_rxdv e4_rxer}]
set_input_delay -clock e4_rx_clk -min 0.5 [get_ports {e4_rxd[*] e4_rxdv e4_rxer}]
set_output_delay -clock e4_gtx_clk -max 2.0 [get_ports {e4_txd[*] e4_txen e4_txer}]
set_output_delay -clock e4_gtx_clk -min 0.0 [get_ports {e4_txd[*] e4_txen e4_txer}]
set_output_delay -clock e4_mii_tx_clk -max 15.0 -add_delay [get_ports {e4_txd[*] e4_txen e4_txer}]
set_output_delay -clock e4_mii_tx_clk -min 0.0 -add_delay [get_ports {e4_txd[*] e4_txen e4_txer}]

# QSPI flash (flash_spi.sv): SCK is 10 MHz, made in logic (HALF_CLKS = 4,
# 50 ns per half period) and sent through STARTUPE2 to CCLK; CS and MOSI
# change half an SCK period before the edge the flash samples, MISO is read
# half a period after it changes. A pin path of one system clock (12.5 ns)
# keeps all of that: time them against sys_clk with no external delay
set_output_delay -clock $sys_clk 0.0 [get_ports {qspi_cs qspi_d0}]
set_input_delay -clock $sys_clk 0.0 [get_ports qspi_d1]
# Asynchronous to every clock, each with its own synchronizer (uart.sv
# uart_rx_ff, the key debouncer) or read by a person (LEDs)
set_false_path -from [get_ports {uart_rx key_in[*]}]
set_false_path -to [get_ports {uart_tx led[*]}]
