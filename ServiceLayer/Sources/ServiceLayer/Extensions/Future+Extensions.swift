// Copyright © 2023 Vyr Cossont. All rights reserved.

import Combine
import Foundation

extension Future {
    public convenience init(async closure: @Sendable @escaping () async -> Output) {
        self.init { promise in
            Task {
                let result = await closure()
                promise(.success(result))
            }
        }
    }

    public convenience init(asyncThrows closure: @Sendable @escaping () async throws -> Output) where Failure == Error {
        self.init { promise in
            Task {
                do {
                    let result = try await closure()
                    promise(.success(result))
                } catch {
                    promise(.failure(error))
                }
            }
        }
    }
}
