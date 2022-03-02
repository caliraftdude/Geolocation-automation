<div id="top"></div>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links


-->


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/othneildrew/Best-README-Template">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Geolocation Database Automation for F5</h3>

  <p align="center">
    Geolocation DB automation example for F5 Big-IPs
    <br />
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](image)

Management of the geolcation database files can sometimes be diffficult as they are not by default included in
UCS files (althoguht they can).  At times there is a need for automating the installation of said files and
this is an examnple of how to do so.

Here's why:
* The Geolocation db files are very large, and while they can be put into a UCS it may be prohibitive to do so
* If you have an RMA or other activity that requires a quick turn around, you don't have time for update processes
* You have an automation or CI/CD system established but you need to include the geolocation dbs

<p align="right">(<a href="#top">back to top</a>)</p>



### Built With

Code will be in python, perhaps other languages in the future.

* [Python](https://www.python.org/)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

This is very simple example code, not a lot to be prepared for.

### Prerequisites

To use this example, you will need:
* Licensed big-ip system (14.1 or greater, but some earlier versions may work)
* Admin access to the big-ip system.  This will use REST interfaces and you will need to get authenticated
* Host system with a python 3 enviroment

### Installation

No installation necessary

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

TBC

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed AS-IS with no guarantee implied or otherwise

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[product-screenshot]: https://i0.wp.com/analystanswers.com/wp-content/uploads/2021/08/markus-spiske-cvBBO4PzWPg-unsplash.jpg?fit=768%2C502&ssl=1
