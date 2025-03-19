# Auth

## Register

- Hash password - bcrypt
- Create user
- Send verification email
- Verify user
- Generate JWT
- Set cookie
- Send response

## Login

- Check if user exists
- Check if password matches - bcrypt
- Check if user is verified
- Generate JWT
- Set cookie
- Send response

## Logout

- Delete cookie
- Send response

## Is Authenticated - In middleware, check if user is authenticated

- Get token from cookie
- Verify token
- Set req.user
- Call next() to move to the next middleware or route handler

## Sendgrid - OK

- Send verification email
- Send reset password email
- Setup in Sendgrid
- Setup in node
- Template

## Reset Password - TODO Later

- Check if user exists
- Generate reset token
- Send reset password email
- Send response
