package io.github.webmasterexit1.kamerkaplus.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = SignalCyan,
    secondary = AccentGold,
    background = DeepNavy,
    surface = SurfaceSlate,
    surfaceVariant = PanelBlue,
)

private val LightColorScheme = lightColorScheme(
    primary = PanelBlue,
    secondary = AccentGold,
    background = ColorWhite,
    surface = ColorWhite,
    surfaceVariant = ColorMist,
)

@Composable
fun KamerkaPlusTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content,
    )
}

