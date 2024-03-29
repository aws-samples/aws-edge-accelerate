# Building Global Web Application based using AWS Edge services

![GamePlay](https://d1zrwss8zuawdm.cloudfront.net/webcard21-play.png)

WebCard21 is an Web-based 1:1 BlackJack game. Have Fun!

Not only source codes for the web-based game, but it also includes AWS best practices to implement online game routing features.

This sample includes how to use AWS Edge services for routing web-based persistent games.
Using Edge services helps you to minimize end-user latency for your game service.

It includes as follows:

- Amazon CloudFront
- Amazon CloudFront Function
- AWS Global Accelerator Custom Routing
- AWS Systems Manager

Pull requests are always welcome. For major changes, please open an issue first to discuss what you would like to change.

## Architecture

![Image](https://d1zrwss8zuawdm.cloudfront.net/webcard21-architecture2.png)

This architecture shows how to implement game servers for Global Service.

- Amazon CloudFront    
 : This helps minimizing end-users accessing latency for your web-based matchmaker.
It caches matchmaking web-pages and accelerates dynamic API for optimized web-based matchmaking.

- Amazon CloudFront Function     
 : In front of Amazon CloudFront, CloudFront Function(CFF) validates end-user's Token before it hits the matchmaker behind. As CFF works at the edge side of Amazon Global Infrastructure, it prevents unverified requests hit matchmaker instances.

- AWS Global Accelerator Custom Routing      
 : AWS Global Accelerator accelerates user traffics to Game Servers on AWS Cloud. It provides Anycast Static IP address pairs for end-users and helps their traffic routing to game servers fastly and consistently. Custom Routing is one of Global Accelerator's features makes deterministic routing for customers. Due to subnet mapping, it is easy to manage scalable game servers behind AWS Global Accelerator.

- AWS Systems Manager       
 : AWS Systems Manager is used for providing target subnet id to Matchmaker. Sample code uses Systems Manager - Parameter Stores, but it is also able to use Database to manage connection information.

- Amazon CloudWatch RUM
 : Amazon CloudWatch RUM is used for measuring end-user experiences for the application. You are able to evaluate end-user performance & errors & session information inside AWS Console Dashboard. You are also integrating AWS X-Ray, Amazon Cognito and Amazon CloudWatch Logs to analyze.

## How to Use

1. You can use this content by cloning the repository or downloading the files.

2. You can also start the content by following the workshop. [English](https://aws-samples.github.io/aws-edge-accelerate/) / [Korean](https://aws-samples.github.io/aws-edge-accelerate/ko/)

- Have fun!

If you have any queries & issues, please feel free to contact me through this repository or email(jinspark@amazon.com). :) 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
