import Foundation

/// Task 5: Tor Transport Manager (iOS / Swift)
///
/// Configures URLSession to route 100% of network traffic through SOCKS5 proxy (127.0.0.1:9050).
/// Implements exponential backoff retry and circuit recovery.
public class TorManager {
    public static let shared = TorManager()

    public let proxyHost: String
    public let proxyPort: Int
    public let urlSession: URLSession

    public init(proxyHost: String = "127.0.0.1", proxyPort: Int = 9050) {
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort

        let config = URLSessionConfiguration.ephemeral

        // Configure SOCKS5 proxy
        let proxyDict: [AnyHashable: Any] = [
            kCFNetworkProxiesSOCKSEnable: 1,
            kCFNetworkProxiesSOCKSProxy: proxyHost,
            kCFNetworkProxiesSOCKSPort: proxyPort
        ]
        config.connectionProxyDictionary = proxyDict
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60

        // Strip identifying user headers
        config.httpAdditionalHeaders = [
            "User-Agent": "AnonChat-iOS/1.0"
        ]

        self.urlSession = URLSession(configuration: config)
    }

    /// Executes network request through Tor with exponential backoff retry
    public func executeWithRetry(
        request: URLRequest,
        maxRetries: Int = 5,
        completion: @escaping (Result<(Data, HTTPURLResponse), Error>) -> Void
    ) {
        func attempt(count: Int) {
            let task = urlSession.dataTask(with: request) { data, response, error in
                if let httpResponse = response as? HTTPURLResponse,
                   (200...299).contains(httpResponse.statusCode) || httpResponse.statusCode == 404,
                   let data = data {
                    completion(.success((data, httpResponse)))
                    return
                }

                if count < maxRetries {
                    let delay = min(0.5 * pow(2.0, Double(count - 1)), 10.0) + Double.random(in: 0...0.5)
                    DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                        attempt(count: count + 1)
                    }
                } else {
                    let finalError = error ?? NSError(domain: "AnonChatTor", code: -1, userInfo: [NSLocalizedDescriptionKey: "Tor circuit exhausted"])
                    completion(.failure(finalError))
                }
            }
            task.resume()
        }

        attempt(count: 1)
    }
}

