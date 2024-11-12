"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const zod_1 = __importDefault(require("zod"));
const mongoose_1 = __importDefault(require("mongoose"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const web3_js_1 = require("@solana/web3.js");
const bs58_1 = __importDefault(require("bs58"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const cors_1 = __importDefault(require("cors"));
const app = (0, express_1.default)();
const SECRET = "secret";
app.use(express_1.default.json());
app.use((0, cors_1.default)());
const User = zod_1.default.object({
    username: zod_1.default.string().email(),
    password: zod_1.default.string().min(6)
});
mongoose_1.default.connect();
const userSchema = new mongoose_1.default.Schema({
    username: String,
    password: String,
    privateKey: String
});
const userDb = mongoose_1.default.model('User', userSchema);
function schemaValidation(req, res, next) {
    try {
        const payload = User.safeParse(req.body);
        if (!payload.success) {
            res.status(400).json({ message: "Invalid credentials" });
        }
        next();
    }
    catch (err) {
        console.log(err);
    }
}
function generateKey() {
    const key = web3_js_1.Keypair.generate();
    return key;
}
app.post("/api/v1/signup", schemaValidation, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const existingUser = yield userDb.findOne({ username: req.body.username });
        if (existingUser) {
            res.status(400).json({ message: "User already exists." });
            return;
        }
        ;
        const userKey = generateKey();
        const privateKey = new Uint8Array(userKey.secretKey);
        const hash = yield bcrypt_1.default.hash(req.body.password, 10);
        const user = new userDb({
            username: req.body.username,
            password: hash,
            privateKey: bs58_1.default.encode(privateKey)
        });
        yield user.save();
        res.status(200).json({ message: "Success", publickey: userKey.publicKey.toBase58() });
    }
    catch (err) {
        console.log(err);
    }
}));
app.post("/api/v1/signin", schemaValidation, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const existingUser = yield userDb.findOne({ username: req.body.username });
        if (!existingUser) {
            res.status(400).json({ message: "User does not exists. Sign in!" });
            return;
        }
        ;
        const result = yield bcrypt_1.default.compare(req.body.password, existingUser.password);
        if (!result) {
            res.status(400).json({ message: "Incorrect password!" });
            return;
        }
        const token = jsonwebtoken_1.default.sign(SECRET, existingUser.privateKey);
        if (typeof window !== 'undefined') {
            console.log('Currently on Client side');
            localStorage.setItem("jwt", token);
        }
        else {
            console.log('Currently on Server Side');
        }
        const userKeypair = web3_js_1.Keypair.fromSecretKey(bs58_1.default.decode(existingUser.privateKey));
        res.status(200).json({ message: "Success", jwt: token, publicKey: userKeypair.publicKey.toBase58() });
    }
    catch (err) {
        console.log(err);
    }
}));
app.post("/api/v1/txn/sign", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const existingUser = yield userDb.findOne({ username: req.body.username });
        const signerKeypair = web3_js_1.Keypair.fromSecretKey(bs58_1.default.decode(existingUser === null || existingUser === void 0 ? void 0 : existingUser.privateKey));
        const toPublicKey = new web3_js_1.PublicKey(req.body.publicKey);
        const url = (0, web3_js_1.clusterApiUrl)("devnet");
        const connection = new web3_js_1.Connection(url);
        const transaction = new web3_js_1.Transaction().add(web3_js_1.SystemProgram.transfer({
            fromPubkey: signerKeypair.publicKey,
            toPubkey: toPublicKey,
            lamports: web3_js_1.LAMPORTS_PER_SOL / 10000
        }));
        const signature = yield (0, web3_js_1.sendAndConfirmTransaction)(connection, transaction, [signerKeypair]);
        console.log("Signature: ", signature);
        res.status(200).json({ message: "Transaction Completed", signature: signature });
    }
    catch (err) {
        console.log(err);
    }
}));
app.post("/api/v2/txn/sign", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const url = (0, web3_js_1.clusterApiUrl)("devnet");
        const connection = new web3_js_1.Connection(url);
        const existingUser = yield userDb.findOne({ username: req.body.username });
        const signerKeypair = web3_js_1.Keypair.fromSecretKey(bs58_1.default.decode(existingUser === null || existingUser === void 0 ? void 0 : existingUser.privateKey));
        const serializedTx = Buffer.from(req.body.message);
        const tx = web3_js_1.Transaction.from(serializedTx);
        const signature = yield (0, web3_js_1.sendAndConfirmTransaction)(connection, tx, [signerKeypair]);
        console.log("Signature: ", signature);
        res.status(200).json({ message: "Success", signature: signature });
    }
    catch (err) {
        console.log(err);
        res.status(400).json({ message: "Error" });
    }
}));
app.listen(3000);
