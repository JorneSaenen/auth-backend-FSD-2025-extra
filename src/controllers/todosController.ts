import { Request, Response } from "express";
import { Todo } from "../models/TodoModel";

export const getAllTodos = async (
  req: Request,
  res: Response
): Promise<any> => {
  try {
    // Retrieve the authenticated user object from the request
    const user = req.user;

    // If the user is not authenticated, return a 401 Unauthorized response
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Find all todos associated with the authenticated user's ID
    const todos = await Todo.find({ userId: user._id });

    // Return the todos
    res.status(200).json(todos);
  } catch (error: unknown) {
    // Handle any errors that occur during the process
    if (error instanceof Error) {
      res.status(500).json({ message: error.message });
    } else {
      res.status(500).json({ message: "Something went wrong" });
    }
  }
};
