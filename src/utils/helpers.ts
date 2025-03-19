import jwt from "jsonwebtoken";
import { Types } from "mongoose";
import * as ms from "ms";
import {
  FROM_EMAIL,
  SENDGRID_API_KEY,
  SENDGRID_TEMPLATE_ID_RESET,
  SENDGRID_TEMPLATE_ID_VERIFY,
} from "./env";
import sgMail from "@sendgrid/mail";

interface UserPayload {
  _id: Types.ObjectId;
  email: string;
  name: string;
}

interface Params {
  user: UserPayload;
  secret: string;
  expiresIn: number | ms.StringValue | undefined;
}

export const signToken = ({ user, secret, expiresIn }: Params) => {
  const token = jwt.sign(user, secret, { expiresIn });
  return token;
};

interface MailContent {
  type: string;
  value: string;
}

interface EmailData {
  name: string;
  email: string;
  link: string;
  type: "verify" | "reset_password";
}

export const sendEmail = async (data: EmailData) => {
  sgMail.setApiKey(SENDGRID_API_KEY as string);
  try {
    const msg = {
      from: FROM_EMAIL as string,
      template_id:
        data.type === "verify"
          ? SENDGRID_TEMPLATE_ID_VERIFY
          : SENDGRID_TEMPLATE_ID_RESET,
      personalizations: [
        {
          to: [
            {
              email: data.email,
            },
          ],
          dynamic_template_data: {
            ...data,
            date: new Date().toLocaleDateString("nl-BE"),
          },
        },
      ],
      content: [
        {
          type: "text/html",
          value: "<p>This is a placeholder content.</p>",
        },
      ] as [MailContent],
    };
    JSON.stringify(msg.personalizations);
    await sgMail.send(msg);
  } catch (error) {
    console.error(error);
  }
};
