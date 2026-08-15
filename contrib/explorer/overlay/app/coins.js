"use strict";

const qbtc = require("./coins/qbtc.js");

module.exports = {
	"QBTC": qbtc,
	"BTC": qbtc, // fallback if BTCEXP_COIN not set

	"coins": ["QBTC", "BTC"]
};
