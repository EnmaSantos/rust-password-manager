## Overview

**Project Title**: Rust Password Manager

**Project Description**:  
This is a command-line password manager built in Rust. It lets you save and retrieve passwords securely. The program uses AES-256-GCM encryption to protect passwords and stores each entry (service name, username, and encrypted password) in a local file.

**Project Goals**:
- To create a simple and secure password manager.
- To practice Rust basics like variables, loops, functions, vectors, and `match`.
- To show how to handle errors and use encryption in Rust.

---

## Instructions for Build and Use

### Steps to Build and Run the Software:

1. Clone the repository and go to the project folder.
2. Make sure you have Rust installed (see the [Development Environment](#development-environment) section).
3. In the terminal, run the following command to build and start the program:
   ```sh
   cargo run

### Instructions for Using the Software:

1. Start the program by running `cargo run`.
2. Type `add` to add a new password. The program will ask you for the service name, username, and password.
3. Type `retrieve` to view saved passwords. The program will decrypt and display each password along with the service name and username.
4. Type `quit` to exit the program.

---

## Development Environment

To recreate the development environment, you need the following:

* **Rust**: Version 1.56 or later
* **Cargo**: Version 1.56 or later (comes with Rust)
* **ring** crate: For encryption (listed in `Cargo.toml`)
* **argon2** crate (optional): For password hashing if you add a login feature later

---

## Useful Websites to Learn More

These websites helped me while working on this project:

* **[Rust Documentation](https://doc.rust-lang.org/book/)** - Official Rust docs, useful for learning Rust basics and ownership rules.
* **[The `ring` crate documentation](https://briansmith.org/rustdoc/ring/)** - Documentation for `ring`, which handles encryption in this project.
* **[Rust by Example](https://doc.rust-lang.org/rust-by-example/)** - Examples and syntax for common Rust patterns.

---

## Future Work

I plan to make the following improvements:

* [ ] Add a master password login for extra security.
* [ ] Use a `struct` to organize each password entry better.
* [ ] Use an `enum` to manage different commands (Add, Retrieve, Quit).
* [ ] Allow updates and deletions of saved passwords.
* [ ] Improve error messages.
* [ ] Consider using a more secure way to store files or manage encryption keys.
