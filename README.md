# Starling Protocol

The Starling protocol is an open standard suitable for anonymous
ad-hoc routing in an unstructured peer-to-peer network. It is optimized
for use in low-bandwidth environments, and it has been specifically
designed for use with smartphones using Bluetooth Low Energy for the
link layer.

This repository contains an implementation of the Starling protocol in Go.
It has been implemented as a generic library that can be integrated with any environment.
This allows for the protocol to be run on actual devices, by integrating the protocol with an environment that interacts over Bluetooth with other devices.
An example of this can be seen in [https://github.com/starling-protocol/starling-messenger](https://github.com/starling-protocol/starling-messenger).
It also enables us to run the exact same code in a simulated environment using a simulator such as [https://github.com/starling-protocol/simulator](https://github.com/starling-protocol/simulator).
