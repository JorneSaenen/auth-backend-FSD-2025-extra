import express from "express";
import {
  forgotPassword,
  login,
  logout,
  register,
} from "../controllers/authController";

const router = express.Router();

router
  .post("/register", register)
  .get("/logout", logout)
  .post("/login", login)
  .post("/reset", forgotPassword);

export default router;
