export {};

export interface User {
  _id: string;
  email: string;
  name: string;
}

declare global {
  namespace Express {
    export interface Request {
      user?: User;
    }
  }
}
