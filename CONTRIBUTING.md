# Contributing to the Ethereum Wireshark Dissectors

### Table of Contents

[Code of Conduct](#code-of-conduct)

[How to Contribute](#how-to-contribute)

* [Reporting Bugs](#reporting-bugs)
* [Suggesting Enhancements](#suggesting-enhancements)
* [Pull Requests](#pull-requests)

[Styleguides](#styleguides)

* [C Styleguide](#c-styleguide)
* [Documentation Styleguide](#documentation-styleguide)

## Code of Conduct

* This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, 
you are agreeing to uphold this code. Please report unacceptable behavior.

## How to contribute

### Reporting bugs

#### Before submitting a bug report

* Ensure the bug is not already reported by searching on GitHub under 
[Issues](https://github.com/consensys/ethereum-dissectors/issues).

#### How do I submit a (good) bug report?

* If you are unable to find an open issue addressing the problem, open a new one. Be sure to include a 
**title and clear description**, as much relevant information as possible, and a **code sample** or 
an **executable test case** demonstrating the unexpected behavior.
* Describe the **exact steps** to **reproduce the problem** in as many details as possible. When 
listing steps, don't just say what you did, but explain how you did it. For example, the exact 
commands used in the terminal to start Orion. 
* Specify the **name and version of the OS** you're using.
* Specify the **version** of Wireshark you're testing against.
* Provide **pcap dumps** of any relevant network captures.
* Provide **specific examples** to demonstrate the steps. Include links to files or GitHub projects, or 
copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, 
use [Markdown code blocks](https://help.github.com/articles/getting-started-with-writing-and-formatting-on-github/).
* Describe the **behavior you observed** after following the steps and explain the 
problem with that behavior.
* Explain the **behavior you expected** instead and why.
* **Can you reliably reproduce the issue?** If not, provide details about how often the problem 
happens and under which conditions it normally happens.

### Suggesting enhancements

#### Before submitting an enhancement suggestion

* [Search](https://github.com/consensys/ethereum-dissectors/issues) to see if the enhancement has already been 
suggested. If it has, add a comment to the existing issue instead of opening a new one.

#### How do I submit a (good) enhancement suggestion?

Enhancement suggestions are tracked as GitHub issues. Create an issue on and provide the following information:

* Use a **clear and descriptive title** for the issue to identify the suggestion.
* Provide a **step-by-step description** of the suggested enhancement in as much detail as possible.
* Describe the **current behavior** and explain the **behavior you expect** instead and why.
* Explain why this enhancement would be useful to other users.
* Specify the **name and version of the OS** you're using.
* Specify the **version** of Wireshark you've developed against.
* Provide **pcap dumps** of any relevant network captures.

### Pull requests

Pull requests will be reviewed by the project team against criteria including:

* Purpose - is this change useful?
* Test coverage - are there unit/integration/acceptance tests demonstrating the change is effective?
* [Style](#c-styleguide)
* Code consistency - naming, comments, design.
* Changes that are solely formatting are likely to be rejected.

**Commit messages:** Always write a clear log message for your commits. One-line messages are fine for small changes, but 
bigger changes should contain more detail. We tend to follow these guidelines where possible:

- https://wiki.openstack.org/wiki/GitCommitMessages
- https://dev.to/shreyasminocha/how-i-do-my-git-commits-34d
- https://gist.github.com/robertpainsi/b632364184e70900af4ab688decf6f53

## Styleguides

### C styleguide

We use the [Google C++ code style](https://google.github.io/styleguide/cppguide.html). If you develop with CLion, you can select the Google C style preset.

### Documentation styleguide

* Use [Markdown](https://daringfireball.net/projects/markdown).
