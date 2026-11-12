//! QR Code Generator for AnonChat Friend Codes

use egui::{Color32, ColorImage};
use qrcode::{Color, QrCode};

/// Renders a string (such as the Friend Code) into an egui-compatible ColorImage.
pub fn generate_qr_image(text: &str) -> Option<ColorImage> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let border = 2;
    let full_width = width + border * 2;
    let scale = 6; // scale up pixels for crisp display
    let final_dim = full_width * scale;

    let mut pixels = vec![Color32::WHITE; final_dim * final_dim];

    let colors = code.to_colors();
    for y in 0..width {
        for x in 0..width {
            let color = match colors[y * width + x] {
                Color::Dark => Color32::BLACK,
                Color::Light => Color32::WHITE,
            };

            // Fill scaled rectangle
            let start_x = (x + border) * scale;
            let start_y = (y + border) * scale;
            for py in 0..scale {
                for px in 0..scale {
                    let idx = (start_y + py) * final_dim + (start_x + px);
                    pixels[idx] = color;
                }
            }
        }
    }

    Some(ColorImage {
        size: [final_dim, final_dim],
        pixels,
    })
}

/// Generates an ASCII representation of the QR code (useful for terminal/logs)
pub fn generate_ascii_qr(text: &str) -> String {
    match QrCode::new(text.as_bytes()) {
        Ok(code) => code
            .render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build(),
        Err(_) => "[QR generation failed]".to_string(),
    }
}

