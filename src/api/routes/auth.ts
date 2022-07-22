import { Router, Request, Response } from 'express';
import { RefreshRequest, SignInRequest, SignUpRequest } from '../../@types/models/AuthRequest';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import db from '../../utils/db';
import config from '../../config';
import { Credentials, TokenInterface } from '../../@types/Auth';
import { getCredentials, validateToken } from '../../utils/token';


const route = Router();

export default (app: Router) => {
    app.use('/auth', route);

    route.post('/signin', async (req: SignInRequest, res: Response) => {
        const { email, password } = req.body;
        if(!email || !password) {
            res.status(400).send({ msg: 'Invalid Fields' });
            return;
        }

        const user = await db.auth.findUnique({
            where: { email }
        });

        if(!user) {
            res.status(404).send({ msg: 'User not found' });
            return;
        }

        const isPwValid = await bcrypt.compare(password, user.pw);

        if(!isPwValid) {
            res.status(401).send({ msg: 'Password Incorrect' });
            return;
        }

        const cred = getCredentials(user.id);

        await db.auth.update({
            where: { id: user.id },
            data: {
                refreshToken: cred.refreshToken
            }
        });

        res.send({
            result: {
                id: user.id,
                email: user.email,
                ...cred
            }
        });
    });

    route.post('/signup', async (req: SignUpRequest, res: Response) => {
        const { email, password } = req.body;
        if(!email || !password) {
            res.status(400).send({ msg: 'Invalid Fields' });
            return;
        }

        const user = await db.auth.findFirst({
            where: { email }
        });

        if(user) {
            res.status(400).send({ msg: 'Email already exists' });
            return;
        }

        const pwHash = await bcrypt.hash(password, 12);

        const newUser = await db.auth.create({
            data: {
                email,
                pw: pwHash
            }
        });

        const cred = getCredentials(newUser.id);

        await db.auth.update({
            where: { id: newUser.id },
            data: {
                refreshToken: cred.refreshToken
            }
        });

        res.send({
            result: {
                id: newUser.id,
                email: newUser.email,
                ...cred
            }
        });
    });

    route.post('/token', async (req: RefreshRequest, res: Response) => {
        const { email, password, refreshToken } = req.body;
        if(!email || !password || !refreshToken) {
            res.status(400).send({ msg: 'Invalid Fields' });
            return;
        }

        const user = await db.auth.findUnique({
            where: { email }
        });

        if(!user) {
            res.status(404).send({ msg: 'User not found' });
            return;
        }

        const isPwValid = await bcrypt.compare(password, user.pw);

        if(!isPwValid) {
            res.status(401).send({ msg: 'Password Incorrect' });
            return;
        }

        const isTokenValid = await validateToken(refreshToken, user.id);

        if(isTokenValid) {
            res.status(401).send({ msg: 'Token Invalid' });
            return;
        }

        const cred = getCredentials(user.id);

        await db.auth.update({
            where: { id: user.id },
            data: {
                refreshToken: cred.refreshToken
            }
        });

        res.send({
            result: {
                id: user.id,
                email: user.email,
                ...cred
            }
        });
    });
}