import dotenv from 'dotenv'
import { generateToken, verifyToken } from './helpers';
dotenv.config()
const { INVITE_TOKEN_SECRET } = process.env;
console.log(generateToken(INVITE_TOKEN_SECRET))
