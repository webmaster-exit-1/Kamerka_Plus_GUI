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
        val activity = composeTestRule.activity

        composeTestRule.onNodeWithText(activity.getString(R.string.app_name)).assertIsDisplayed()
        composeTestRule.onNodeWithText(activity.getString(R.string.hero_title)).assertIsDisplayed()
        composeTestRule.onNodeWithText(activity.getString(R.string.feature_section_title)).assertIsDisplayed()
        composeTestRule.onNodeWithText(activity.getString(R.string.status_section_title)).assertIsDisplayed()
    }
}
