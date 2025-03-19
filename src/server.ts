// Imports
import "dotenv/config";
import cors from "cors";
import express, { Request, Response } from "express";
import { notFound } from "./controllers/notFoundController";
import authRoutes from "./routes/authRoutes";
import todoRoutes from "./routes/todoRoutes";
import { isAuth } from "./middleware/authMiddleware";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import { JWT_SECRET, MONGO_URI } from "./utils/env";
import morgan from "morgan";
import { resetPassword, verificationEmail } from "./controllers/authController";
import ejs from "ejs";
import jwt from "jsonwebtoken";
import { User } from "./models/UserModel";

// Variables
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(morgan("dev"));
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.set("views", "src/views");
app.use(express.static("src/public"));
app.set("view engine", "ejs");

// Routes
app.use("/api", authRoutes);
app.get("/reset/:token", async (req: Request, res: Response) => {
  const { token } = req.params;
  const decoded = jwt.verify(token, JWT_SECRET as string);
  const user = await User.findOne({
    email: (decoded as { email: string }).email,
  });

  res.render("reset", {
    email: user?.email,
  });
});
app.get("/verify/:token", verificationEmail);
app.post("/reset-password", resetPassword);
app.use("/api/todos", isAuth, todoRoutes);
app.all("*", notFound);

// Database connection
try {
  await mongoose.connect(MONGO_URI!);
  console.log("Database connection OK");
} catch (err) {
  console.error(err);
  process.exit(1);
}

// Server Listening
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}! 🚀`);
});
