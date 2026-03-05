import { IUserDoc } from "..";

declare global {
  namespace Express {
    interface User extends IUserDoc {}
  }
}