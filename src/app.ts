/* eslint-disable no-undef */
/* eslint-disable no-unused-vars */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Application, Request, Response } from 'express';
import globalErrorHandler from './app/middleware/globalErrorhandler';
import notFound from './app/middleware/notfound';
import router from './app/routes';
import auth from './app/middleware/auth';
import { USER_ROLE } from './app/modules/user/user.constants';
import { User } from './app/modules/user/user.models';
import SimpleWebAuthnServer, {
  generateAuthenticationOptions,
} from '@simplewebauthn/server';
import sendResponse from './app/utils/sendResponse';
import httpStatus from 'http-status';
import crypto from 'node:crypto';

if (!globalThis.crypto) {
  //@ts-ignore
  globalThis.crypto = crypto;
}
const app: Application = express();
app.use(express.static('public'));

//parsers
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  }),
);

// application routes
app.use('/api/v1', router);

app.post('/register-challenge', auth(USER_ROLE.user), async (req, res) => {
  const user = await User.findById(req.user.userId);
  const challengePayload = await generateAuthenticationOptions({
    rpID: 'localhost',
    //@ts-ignore
    rpName: 'My LocalHost Machine',
    userName: user?.email,
  });
  console.log(user);
  await User.findByIdAndUpdate(user?._id, {
    challenge: challengePayload?.challenge,
  });
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Challenge created successfully',
    data: { options: challengePayload },
  });
});

app.get('/', (req: Request, res: Response) => {
  res.send('server is running');
});
app.use(globalErrorHandler);

//Not Found
app.use(notFound);

export default app;
