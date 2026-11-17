# SPDX-FileCopyrightText: 2026 Chili.CHIPS*ba
# 
# SPDX-License-Identifier: BSD-3-Clause

open_project wireguard.xpr

reset_run synth_1
reset_run impl_1

launch_runs synth_1 -jobs 6
wait_on_run synth_1

launch_runs impl_1 -to_step write_bitstream -jobs 6
wait_on_run impl_1

exit

# -----------------------------------------------------------------------------
# Project:     WireGuard-FPGA
# Description: NLnet-funded open-source implementation
# Funding:     https://nlnet.nl/project/KlusterLab-Wireguard (2023-12 to 2025-12)
# -----------------------------------------------------------------------------
