package io.github.webmasterexit1.kamerkaplus

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import org.junit.Rule
import org.junit.Test

class MainActivityTest {

    @get:Rule
    val composeTestRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun mainScreenShowsPrimarySections() {
        composeTestRule.onNodeWithText("Kamerka Plus").assertIsDisplayed()
        composeTestRule.onNodeWithText("Mobile recon workspace").assertIsDisplayed()
        composeTestRule.onNodeWithText("Planned modules").assertIsDisplayed()
        composeTestRule.onNodeWithText("Project status").assertIsDisplayed()
    }
}
