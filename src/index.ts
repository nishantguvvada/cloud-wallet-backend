import express from "express";
import zod from "zod";
import mongoose from "mongoose";
import jsonwebtoken from "jsonwebtoken";
import { Keypair, clusterApiUrl, Transaction, sendAndConfirmTransaction, Connection, SystemProgram, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const SECRET = "";

app.use(express.json());
app.use(cors());

const User = zod.object({
    username: zod.string().email(),
    password: zod.string().min(6)
});

mongoose.connect(
    "",
);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    privateKey: String
})

const userDb = mongoose.model('User', userSchema);

function schemaValidation(req: any, res: any, next: any) {
    try {
        const payload = User.safeParse(req.body);
        if (!payload.success) {
            res.status(400).json({message: "Invalid credentials"});
        }
        next();
    } catch(err) {
        console.log(err);
    }
}

function generateKey() {
    const key = Keypair.generate();
    return key;
}

app.post("/api/v1/signup", schemaValidation, async (req, res) => {
    try {

        const existingUser = await userDb.findOne({ username: req.body.username });

        if (existingUser) {
            res.status(400).json({message: "User already exists."});
            return
        };

        const userKey = generateKey();

        const privateKey = new Uint8Array(userKey.secretKey);

        const hash = await bcrypt.hash(req.body.password, 10);

        const user = new userDb({
            username: req.body.username,
            password: hash,
            privateKey: bs58.encode(privateKey)
        });

        await user.save();

        res.status(200).json({message: "Success", publickey: userKey.publicKey.toBase58()});
    } catch(err) {
        console.log(err);
    }
});

app.post("/api/v1/signin", schemaValidation, async (req, res) => {
    try {

        const existingUser = await userDb.findOne({ username: req.body.username });

        if (!existingUser) {
            res.status(400).json({message: "User does not exists. Sign in!"});
            return
        };

        const result = await bcrypt.compare(req.body.password, existingUser.password!)

        if (!result) {
            res.status(400).json({message: "Incorrect password!"});
            return
        }

        const token = jsonwebtoken.sign(SECRET, existingUser.privateKey!);

        if (typeof window !== 'undefined') {
            console.log('Currently on Client side');
            localStorage.setItem("jwt", token);
        } else {
            console.log('Currently on Server Side');
        }

        const userKeypair = Keypair.fromSecretKey(bs58.decode(existingUser.privateKey!));

        res.status(200).json({message: "Success", jwt: token, publicKey: userKeypair.publicKey.toBase58()});
    } catch(err) {
        console.log(err);
    }
});

app.post("/api/v1/txn/sign", async (req, res) => {

    try {
        const existingUser = await userDb.findOne({username: req.body.username});
        const signerKeypair = Keypair.fromSecretKey(bs58.decode(existingUser?.privateKey!));
        const toPublicKey = new PublicKey(req.body.publicKey);

        const url = clusterApiUrl("devnet");
        const connection = new Connection(url);

        const transaction = new Transaction().add(
            SystemProgram.transfer({
                fromPubkey: signerKeypair.publicKey,
                toPubkey: toPublicKey,
                lamports: LAMPORTS_PER_SOL / 10000   
            })
        );

        const signature = await sendAndConfirmTransaction(connection, transaction, [signerKeypair]);

        console.log("Signature: ", signature);

        res.status(200).json({message: "Transaction Completed", signature: signature});

    } catch(err) {
        console.log(err);
    }

});

app.post("/api/v2/txn/sign", async (req, res) => {
    try {
        const url = clusterApiUrl("devnet");
        const connection = new Connection(url);

        const existingUser = await userDb.findOne({username: req.body.username});
        const signerKeypair = Keypair.fromSecretKey(bs58.decode(existingUser?.privateKey!));

        const serializedTx = Buffer.from(req.body.message);
        const tx = Transaction.from(serializedTx);

        const signature = await sendAndConfirmTransaction(connection, tx, [signerKeypair]); 

        console.log("Signature: ", signature);

        res.status(200).json({message: "Success", signature: signature});

    } catch(err) {
        console.log(err);
        res.status(400).json({message: "Error"});
    }
});

app.listen(3000);