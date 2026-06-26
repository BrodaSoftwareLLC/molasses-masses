# :honey_pot: Project Molasses-Masses

## :globe_with_meridians: Overview

Project Molasses-Masses is designed to provide a dynamically updated list of hosting providers from around the world. This list is based on the prefixes advertised as part of the BGP Autonomous System numbers.

Acknowledging that hosting providers themselves are not inherently problematic, some of their customers may have malicious intentions. Therefore, we adopt a "block first" approach, creating exceptions to allow legitimate traffic through as needed.

This project is currently tracking `17574` IPv4 Subnets and `2839` IPv6 Subnets.

## :hammer_and_wrench: How It Works

The project uses a Python script to fetch and process IP prefixes associated with various hosting providers.

## :bulb: To Access
Please browse to [Broda Software LLC](https://broda.io/products/molasses-masses)'s website to request a 7 day free trial.

## :warning: Disclaimer

This project is not meant to imply that all traffic from hosting providers is malicious. It's a tool for those who prefer a cautious approach to network traffic, allowing for precise control and whitelisting as needed. If you leverage cloud hosted services, then it is up to you to filter out your applicable IP addresses/subnets from the list. I cannot be held liable for any actions of this block list.

## :fire: Shorewall Blocklist

A bash script `molasses-masses-shorewall.sh` will help download the files and update shorewall rules to reflect the list of subnets that should be blocked. It should only update the list of iptables if the files hosted on Cloudflare have been updated.

## :handshake: Contributing

Contributions to Project Molasses-Masses are welcome! Please feel free to submit pull requests or open issues to improve the project.
