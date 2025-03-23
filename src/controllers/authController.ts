import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { User } from "../models/UserModel";
import { sendEmail, sendEmail2, signToken } from "../utils/helpers";
import { BASE_URL, JWT_SECRET } from "../utils/env";
import jwt from "jsonwebtoken";

const saltRounds = 10;

export const register = async (req: Request, res: Response) => {
  // This function creates a new user when the `/register` endpoint is hit.
  // It takes in a request and response object as arguments.
  try {
    // Destructure the request body into name, email, and password.
    // If any of these fields are missing, return a 400 status and an
    // error message.
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }

    // Hash the user's password using bcrypt. This is a
    // one-way encryption, so we can't reverse it.
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const verificationToken = jwt.sign({ email }, JWT_SECRET as string, {
      expiresIn: "1h",
    });

    const verificationLink = `${BASE_URL}/verify/${verificationToken}`;

    await sendEmail2({
      name,
      email,
      type: "verify",
      link: verificationLink,
    });

    // Create a new user in the database using the User model.
    // The `create` method is a Mongoose method that takes an object
    // and creates a new document in the database with the fields
    // specified in the object.
    const response = await User.create({
      name,
      email,
      password: hashedPassword,
      verificationToken,
    });

    // If the JWT_SECRET environment variable is not set, throw an
    // error. This is a security risk, as it would allow anyone to
    // create a JWT token and access the API.
    if (!JWT_SECRET) {
      throw new Error("Internal error");
    }

    // Create a new user object that we will use to generate the JWT.
    // This object will contain the user's ID, email, and name.
    const user = {
      _id: response._id,
      email: response.email,
      name: response.name,
    };

    // Generate a JWT token using the signToken function. This function
    // takes the user object and the JWT_SECRET as arguments.
    const token = signToken({
      user: user,
      secret: JWT_SECRET,
      expiresIn: "7d",
    });

    // Set a cookie with the token, accessible only via HTTP, secure in production
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Return a 201 status (created) and the user object.
    res
      .status(201)
      .json({ message: "User created successfully", user: response });
  } catch (error: unknown) {
    // If an error occurs, catch it and return a 500 status with an
    // error message.
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    // Destructure email and password from the request body
    const { email, password } = req.body;

    // Check if email and password are provided, return 400 error if not
    if (!email || !password) {
      res.status(400).json({ message: "Please fill all fields" });
      return;
    }

    // Find the user in the database by email
    const user = await User.findOne({ email });

    // If user is not found, return 400 error
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }

    if (!user.isVerified) {
      res.status(400).json({ message: "Email is not verified!" });
      return;
    }

    // Compare the provided password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);

    // If passwords do not match, return 400 error
    if (!isMatch) {
      res.status(400).json({ message: "Invalid credentials" });
      return;
    }

    // Ensure the SECRET environment variable is set
    if (!JWT_SECRET) {
      throw new Error("Internal error");
    }

    // Create a user object for the token
    const tokenUser = {
      _id: user._id,
      email: user.email,
      name: user.name,
    };

    // Generate a JWT token with the user object, secret, and expiration
    const token = signToken({
      user: tokenUser,
      secret: JWT_SECRET,
      expiresIn: "7d",
    });

    // Set a cookie with the token, accessible only via HTTP, secure in production
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Respond with a success message
    res.status(200).json({ message: "User logged in successfully" });
  } catch (error: unknown) {
    // Handle any errors during the process and respond with a 500 error
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    // Set the token to an empty string, and set the maxAge to 1, which
    // means the cookie will expire in 1 second.
    res.cookie("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production" ? true : false,
      sameSite: "none",
      maxAge: 1,
    });

    // Respond with a success message
    res.status(200).json({ message: "User logged out successfully" });
  } catch (error: unknown) {
    // Handle any errors that may occur during the logout process
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const verificationEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.params;
    if (!token) {
      res.status(400).json({ message: "Invalid token" });
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET as string);

    if (typeof decoded === "string" || !("email" in decoded)) {
      res.status(400).json({ message: "Invalid verification link." });
      return;
    }
    const user = await User.findOne({ email: decoded.email });
    if (!user) {
      res.status(400).json({ message: "No user found!" });
      return;
    }
    if (user.isVerified) {
      res.status(400).json({ message: "Is already verified!" });
      return;
    }
    user.verificationToken = null;
    user.isVerified = true;
    await user.save();
    res.status(200).json({
      message: "Email is verified",
    });
    // res.redirect(
    //   "https://global.discourse-cdn.com/auth0/original/3X/6/9/69d4cd962892823265f21e8fed1915c5e903d31f.png"
    // );
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ message: "Email is required" });
      return;
    }
    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).json({ message: "No user found" });
      return;
    }
    if (!user.isVerified) {
      res.status(400).json({ message: "User is not verified" });
      return;
    }
    const resetToken = jwt.sign({ email }, JWT_SECRET as string, {
      expiresIn: "15m",
    });
    const resetLink = `${BASE_URL}/reset/${resetToken}`;

    await sendEmail({
      name: user.name,
      email,
      type: "reset_password",
      link: resetLink,
    });
    user.resetToken = resetToken;
    await user.save();
    res.status(200).json({ message: "Email sent successfully" });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { password, email } = req.body;
    if (!password || !email) {
      res.status(400).json({ message: "fields are required" });
      return;
    }

    const user = await User.findOne({ email });
    if (!user) {
      res.status(400).json({ message: "No user found!" });
      return;
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    user.password = hashedPassword;
    user.resetToken = null;
    await user.save();
    res.status(200).json({ message: "Password reset successfully" });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
