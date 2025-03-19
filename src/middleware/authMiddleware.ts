import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { User } from "../types/request";
const { JWT_SECRET } = process.env;

export const isAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // The purpose of this middleware is to verify if the user is authenticated.
    // We do this by checking if a token is present in the cookies.
    const token = req.cookies.token;
    if (!token) {
      // If no token is present, return an error of Unauthorized.
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    // If we have a token, we verify it with the JWT_SECRET.
    if (!JWT_SECRET) {
      throw new Error("Internal error");
    }
    // The jwt.verify function will throw an error if the token is invalid.
    // We catch this error and handle it by returning an Unauthorized error.
    const user = jwt.verify(token, JWT_SECRET);
    if (!user) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const userObject: User = {
      _id: (user as JwtPayload)._id,
      email: (user as JwtPayload).email,
      name: (user as JwtPayload).name,
    };

    // If the token is valid, we store the user in the request object.
    // This allows us to access the user in the following middleware.
    req.user = userObject;
    // We call the next function to continue to the next middleware.
    next();
  } catch (error: unknown) {
    // If we catch an error, we handle it by returning an error.
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
