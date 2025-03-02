// Copyright © 2020 Metabolist. All rights reserved.

import Combine
import DB
import Foundation
import Mastodon
import MastodonAPI

public struct SearchService {
    public let sections: AnyPublisher<[CollectionSection], Error>
    public let navigationService: NavigationService
    public let nextPageMaxId: AnyPublisher<String, Never>

    private let mastodonAPIClient: MastodonAPIClient
    private let contentDatabase: ContentDatabase
    private let nextPageMaxIdSubject = PassthroughSubject<String, Never>()
    private let resultsSubject = PassthroughSubject<(Results, Search), Error>()

    init(environment: AppEnvironment, mastodonAPIClient: MastodonAPIClient, contentDatabase: ContentDatabase) {
        self.mastodonAPIClient = mastodonAPIClient
        self.contentDatabase = contentDatabase
        nextPageMaxId = nextPageMaxIdSubject.eraseToAnyPublisher()
        navigationService = NavigationService(environment: environment,
                                              mastodonAPIClient: mastodonAPIClient,
                                              contentDatabase: contentDatabase)
        sections = resultsSubject.scan((.empty, nil)) {
            let (results, search) = $1

            return (search.offset == nil ? results : $0.0.appending(results), search.limit)
        }
        .map(contentDatabase.publisher(results:limit:)).switchToLatest().eraseToAnyPublisher()
    }
}

extension SearchService: CollectionService {
    public func request(maxId: String?, minId: String?, search: Search?) -> AnyPublisher<Never, Error> {
        guard
            let search = search,
            !search.query.trimmingCharacters(in: .whitespaces).isEmpty
        else { return Empty().eraseToAnyPublisher() }

        return mastodonAPIClient.request(ResultsEndpoint.search(search))
            .flatMap { results in contentDatabase.insert(results: results).collect().map { _ in results } }
            .flatMap { results in
                if !results.accounts.isEmpty {
                    return mastodonAPIClient
                        .request(RelationshipsEndpoint.relationships(ids: results.accounts.map { $0.id }))
                        .flatMap(contentDatabase.insert(relationships:))
                        .collect()
                        .map { _ in results }
                        .eraseToAnyPublisher()
                } else {
                    return Just(results)
                        .setFailureType(to: Error.self)
                        .eraseToAnyPublisher()
                }
            }
            .flatMap { results in
                if !results.accounts.isEmpty {
                    return mastodonAPIClient
                        .request(FamiliarFollowersEndpoint.familiarFollowers(ids: results.accounts.map { $0.id }))
                        .flatMap(contentDatabase.insert(familiarFollowers:))
                        .collect()
                        .map { _ in results }
                        .eraseToAnyPublisher()
                } else {
                    return Just(results)
                        .setFailureType(to: Error.self)
                        .eraseToAnyPublisher()
                }
            }
            .handleEvents(receiveOutput: { resultsSubject.send(($0, search)) })
            .ignoreOutput()
            .eraseToAnyPublisher()
    }
}
