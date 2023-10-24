# 🚀 Rocket CSRF Protection Example

🛡️ This is a simple demonstration of how Rocket helps protect your web application against Cross-Site Request Forgery (CSRF) attacks.

## 🏁 Getting Started

1. **Build and Run the Project:** Start the application using Cargo:

   ```bash
   cargo run
   ```

1. **Access the Application:** Your Rocket application should be up and running. Open your web browser and visit `http://127.0.0.1:8000`.

![App Demo](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/lcpfehq4rsjpwrjjehvr.png)

## 🔒 CSRF Protection

This project incorporates robust CSRF protection mechanisms. CSRF attacks occur when unauthorized requests are made on behalf of a user without their consent. Rocket's CSRF protection ensures that form submissions contain a valid CSRF token, significantly enhancing the security of your web forms. 🌐

## 🧪 Testing CSRF Protection

To test the CSRF protection, you can use the following `curl` command:

```bash
curl -X POST -d "authenticity_token=invalid&text=sus" http://127.0.0.1:8000/comments
```

Running this command will result in a "403 Forbidden: Unauthorized Access" response. This occurs because the provided `authenticity_token` is invalid, and the CSRF token validation in the application rightfully rejects the request.

## ✅ Successful POST Request

To make a successful POST request, follow these steps:

1. **Obtain a CSRF Token:** In a real application, you would typically obtain a valid CSRF token from a GET request. In our example, the application provides a CSRF token when you access `http://127.0.0.1:8000/comments/new`. You can extract it from the HTML response.

1. **Fill in the Form in Your Browser:** You can fill in the form in your web browser with the CSRF token you obtained. This ensures that your request is processed successfully, and you'll receive a response indicating that the comment has been created. 🎉

![form submit](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/l56i9gg851ggfrnqv5sf.png)

## 📁 Project Structure

- `src/main.rs`: The primary application code.
- `templates/comments/new.html.hbs`: Contains the HTML template for the web page.

This example is designed to provide a straightforward illustration of how Rocket enhances web security through CSRF protection.

Enjoy exploring the project and learning about web security with Rocket! 🚀