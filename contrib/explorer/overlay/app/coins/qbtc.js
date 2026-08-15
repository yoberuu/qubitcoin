"use strict";

const Decimal = require("decimal.js");
const Decimal8 = Decimal.clone({ precision: 8, rounding: 8 });

// QubitCoin block subsidy: 500 QBTC, halving every 210000 blocks (regtest: 150)
const blockRewardEras = [new Decimal8(500)];
for (let i = 1; i < 34; i++) {
	blockRewardEras.push(new Decimal8(blockRewardEras[i - 1]).dividedBy(2));
}

const currencyUnits = [
	{
		type: "native",
		name: "QBTC",
		multiplier: 1,
		default: true,
		values: ["", "qbtc", "QBTC"],
		decimalPlaces: 8
	},
	{
		type: "native",
		name: "sat",
		multiplier: 100000000,
		values: ["sat", "satoshi"],
		decimalPlaces: 0
	},
];

module.exports = {
	name: "QubitCoin",
	ticker: "QBTC",
	logoUrlsByNetwork: {
		"main": "./img/network-mainnet/logo.svg",
		"test": "./img/network-testnet/logo.svg",
		"testnet4": "./img/network-testnet/logo.svg",
		"regtest": "./img/network-regtest/logo.svg",
	},
	coinIconUrlsByNetwork: {
		"main": "./img/network-mainnet/coin-icon.svg",
		"test": "./img/network-testnet/coin-icon.svg",
		"testnet4": "./img/network-testnet/coin-icon.svg",
		"regtest": "./img/network-regtest/coin-icon.svg",
	},
	coinColorsByNetwork: {
		"main": "#6B4EFF",
		"test": "#1daf00",
		"testnet4": "#0088cc",
		"regtest": "#777"
	},
	siteTitlesByNetwork: {
		"main": "QubitCoin Explorer",
		"test": "QubitCoin Testnet3 Explorer",
		"testnet4": "QubitCoin Testnet4 Explorer",
		"regtest": "QubitCoin Regtest Explorer",
	},
	demoSiteUrlsByNetwork: {},
	knownTransactionsByNetwork: {},
	miningPoolsConfigUrls: [],
	maxBlockWeight: 4000000,
	maxBlockSize: 1000000,
	minTxBytes: 5000,
	minTxWeight: 20000,
	difficultyAdjustmentBlockCount: 2016,
	maxSupplyByNetwork: {
		"main": new Decimal(210000000),
		"test": new Decimal(210000000),
		"testnet4": new Decimal(210000000),
		"regtest": new Decimal(210000000),
	},
	targetBlockTimeSeconds: 600,
	targetBlockTimeMinutes: 10,
	currencyUnits: currencyUnits,
	currencyUnitsByName: { "QBTC": currencyUnits[0], "sat": currencyUnits[1] },
	baseCurrencyUnit: currencyUnits[1],
	defaultCurrencyUnit: currencyUnits[0],
	feeSatoshiPerByteBucketMaxima: [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 5000, 10000],
	halvingBlockIntervalsByNetwork: {
		"main": 210000,
		"test": 210000,
		"testnet4": 210000,
		"regtest": 150,
	},
	terminalHalvingCountByNetwork: {
		"main": 32,
		"test": 32,
		"testnet4": 32,
		"regtest": 32
	},
	coinSupplyCheckpointsByNetwork: {
		"main": [0, new Decimal(0)],
		"test": [0, new Decimal(0)],
		"testnet4": [0, new Decimal(0)],
		"regtest": [0, new Decimal(0)]
	},
	utxoSetCheckpointsByNetwork: {},
	genesisBlockHashesByNetwork: {
		"main": "000000002f4fcc60ef61353d1767c691562dd380f240c1fcf47bf0e1c655d011",
		"test": "00000000c0f906a85aca8c26722998dd6292ef5c88f5912963eed730df17f09a",
		"testnet4": "00000000f0760be464eb2acd0069f5fbd4e50638c8b629c5d6ac50966c060636",
		"regtest": "7b9160d5ab91fb4fbe56014bdb86a9dcebafb9cc28c110f91142303f7b472747",
	},
	genesisCoinbaseTransactionIdsByNetwork: {},
	genesisCoinbaseTransactionsByNetwork: {},
	genesisBlockStatsByNetwork: {},
	testData: { txDisplayTestList: {} },
	genesisCoinbaseOutputAddressScripthash: "",
	historicalData: [],
	exchangeRateData: null,
	goldExchangeRateData: null,
	blockRewardFunction: function(blockHeight, chain) {
		let halvingBlockInterval = (chain == "regtest" ? 150 : 210000);
		let index = Math.floor(blockHeight / halvingBlockInterval);
		if (index >= blockRewardEras.length) {
			index = blockRewardEras.length - 1;
		}
		return blockRewardEras[index];
	},
	// QubitCoin Dilithium P2PKH address prefixes (for explorer search routing)
	dilithiumAddressRegex: /^[a-zA-Z][1-9A-HJ-NP-Za-km-z]{25,34}$/,
	bech32HrpRegex: /^(qc|tq|trq|sq|qcrt)1[ac-hj-np-z02-9]{6,87}$/,
};
