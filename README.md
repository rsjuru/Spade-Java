# Spade-Java

Java implementation of the Spade cryptographic scheme, based on an existing Python implementation.

The project is being developed as a Java 21 + Maven project. The goal is to implement the core cryptographic functionality and the associated User, Curator, and Analyst components in Java.

## Project Status

**Work in progress.**

Currently implemented:

- Spade cryptographic core
- Key setup
- Registration key generation
- Encryption
- Key derivation
- Decryption/predicate evaluation
- Curator parameter storage using SQLite
- JUnit tests
- GitHub Actions CI pipeline

Currently under development:

- User functionality
- Analyst functionality
- Data analysis functionality
- HTTP communication between components

## Technologies

- Java 21
- Maven
- JUnit 5
- SQLite
- Git / GitHub
- GitHub Actions

## Project Structure

```text
Spade/
├── .github/
│   └── workflows/
│       └── maven.yml
├── pom.xml
└── src/
    ├── main/
    │   └── java/
    │       └── main/
    │           ├── Spade.java
    │           ├── Curator.java
    │           └── User.java
    └── test/
        └── java/
            └── main/
                ├── SpadeTest.java
                └── CuratorTest.java
```

## Requirements

- Java 21
- Maven 3.10 or newer

Check the installed versions:

```bash
java -version
mvn -version
```

## Build and Test

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/rsjuru/Spade-Java.git
cd Spade-Java
```

Run the tests with Maven:

```bash
mvn clean test
```

The GitHub Actions pipeline also automatically builds the project and runs the tests when changes are pushed or a pull request is created.

## Development

The project uses feature branches for development.

Examples:

```text
main
├── feature-users
├── feature-analyst
└── feature-data-analysis
```