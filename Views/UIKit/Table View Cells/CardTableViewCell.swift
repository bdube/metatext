// Copyright © 2023 Vyr Cossont. All rights reserved.

import UIKit
import ViewModels

final class CardTableViewCell: SeparatorConfiguredTableViewCell {
    var viewModel: CardViewModel?

    override func updateConfiguration(using state: UICellConfigurationState) {
        guard let viewModel = viewModel else { return }

        contentConfiguration = CardContentConfiguration(viewModel: viewModel).updated(for: state)
    }
}
