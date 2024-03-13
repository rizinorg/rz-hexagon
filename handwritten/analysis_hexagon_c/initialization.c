// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

RzAnalysisPlugin rz_analysis_plugin_hexagon = {
	.name = "hexagon",
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.license = "LGPL3",
	.arch = "hexagon",
	.bits = 32,
	.op = hexagon_v6_op,
	.esil = false,
	.get_reg_profile = get_reg_profile,
};
