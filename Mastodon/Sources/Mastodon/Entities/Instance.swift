// Copyright © 2020 Metabolist. All rights reserved.

import Foundation

/// Result of calling the Mastodon v1 instance API, a mix of instance metadata and client configuration.
/// See also: `DB.Identity.Instance` summary version in identity database.
public struct Instance: Codable {
    public struct URLs: Codable, Hashable {
        public let streamingApi: UnicodeURL
    }

    public struct Stats: Codable, Hashable {
        public let userCount: Int
        public let statusCount: Int
        public let domainCount: Int
    }

    public struct Configuration: Codable, Hashable {
        // swiftlint:disable:next nesting
        public struct Statuses: Codable, Hashable {
            public let maxCharacters: Int?

            public init(maxCharacters: Int?) {
                self.maxCharacters = maxCharacters
            }
        }

        public let statuses: Statuses?

        public init(statuses: Statuses?) {
            self.statuses = statuses
        }
    }

    public let uri: String
    public let title: String
    public let description: HTML
    public let shortDescription: String?
    public let email: String
    public let version: String
    @DecodableDefault.EmptyList public private(set) var languages: [String]
    @DecodableDefault.False public private(set) var registrations: Bool
    @DecodableDefault.False public private(set) var approvalRequired: Bool
    @DecodableDefault.False public private(set) var invitesEnabled: Bool
    public let urls: URLs
    public let stats: Stats
    public let thumbnail: UnicodeURL?
    public let contactAccount: Account?
    public var maxTootChars: Int? {
        configuration?.statuses?.maxCharacters
    }
    public let configuration: Configuration?
    @DecodableDefault.EmptyList public private(set) var rules: [Rule]

    public init(
        uri: String,
        title: String,
        description: HTML,
        shortDescription: String?,
        email: String,
        version: String,
        urls: Instance.URLs,
        stats: Instance.Stats,
        thumbnail: UnicodeURL?,
        contactAccount: Account?,
        configuration: Configuration?,
        rules: [Rule]
    ) {
        self.uri = uri
        self.title = title
        self.description = description
        self.shortDescription = shortDescription
        self.email = email
        self.version = version
        self.urls = urls
        self.stats = stats
        self.thumbnail = thumbnail
        self.contactAccount = contactAccount
        self.configuration = configuration
        self.rules = rules
    }
}

extension Instance: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(uri)
    }
}

public extension Instance {
    var majorVersion: Int? {
        guard let majorVersionString = version.split(separator: ".").first else { return nil }

        return Int(majorVersionString)
    }

    var minorVersion: Int? {
        let versionComponents = version.split(separator: ".")

        guard versionComponents.count > 1 else { return nil }

        return Int(versionComponents[1])
    }

    var patchVersion: String? {
        let versionComponents = version.split(separator: ".")

        guard versionComponents.count > 2 else { return nil }

        return String(versionComponents[2])
    }

    var canShowProfileDirectory: Bool {
        guard let majorVersion = majorVersion else { return false }

        return majorVersion >= 3
    }
}
