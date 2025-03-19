import express from "express";
import { getAllTodos } from "../controllers/todosController";

const router = express.Router();

router.get("/", getAllTodos);

export default router;
