package main

// seedProducts returns the VoltStore catalog: 12 realistic tech products
// across 5 categories, with real-world pricing, ratings and stock levels.
func seedProducts() []Product {
	return []Product{
		{
			ID: 1, Name: "MacBook Pro 14\" M3 Max", Category: "laptops",
			PriceCents: 349900, Stock: 12, Rating: 4.9, Reviews: 214, Featured: true, Badge: "Hot",
			Accent:      "#4f46e5",
			Description: "14-inch Liquid Retina XDR display, M3 Max (14-core CPU, 30-core GPU), 36GB unified memory, 1TB SSD. Up to 18 hours of battery life.",
		},
		{
			ID: 2, Name: "iPhone 15 Pro 256GB", Category: "phones",
			PriceCents: 119900, Stock: 48, Rating: 4.8, Reviews: 1893, Featured: true, Badge: "Hot",
			Accent:      "#0ea5e9",
			Description: "6.1-inch Super Retina XDR with ProMotion, A17 Pro chip, titanium design, pro camera system with 5x telephoto.",
		},
		{
			ID: 3, Name: "AirPods Pro (2nd Gen)", Category: "audio",
			PriceCents: 24900, Stock: 120, Rating: 4.7, Reviews: 3421, Featured: true,
			Accent:      "#8b5cf6",
			Description: "Active noise cancellation, adaptive transparency, personalized spatial audio, MagSafe charging case with USB-C.",
		},
		{
			ID: 4, Name: "Dell XPS 13 Plus", Category: "laptops",
			PriceCents: 189900, Stock: 32, Rating: 4.5, Reviews: 412, Featured: true,
			Accent:      "#0f172a",
			Description: "13.4-inch FHD+ InfinityEdge, Intel Core i7-1360P, 16GB RAM, 512GB SSD, 55Wh battery.",
		},
		{
			ID: 5, Name: "Samsung Galaxy S24 Ultra", Category: "phones",
			PriceCents: 129900, Stock: 27, Rating: 4.6, Reviews: 987, Badge: "New",
			Accent:      "#6366f1",
			Description: "6.8-inch QHD+ Dynamic AMOLED 2X, Snapdragon 8 Gen 3, 200MP camera with 100x Space Zoom, S Pen included.",
		},
		{
			ID: 6, Name: "Sony WH-1000XM5", Category: "audio",
			PriceCents: 39900, Stock: 65, Rating: 4.8, Reviews: 2764,
			Accent:      "#334155",
			Description: "Industry-leading noise cancellation, 30-hour battery, multipoint connection, premium comfort.",
		},
		{
			ID: 7, Name: "Logitech MX Master 3S", Category: "peripherals",
			PriceCents: 9999, Stock: 200, Rating: 4.7, Reviews: 5230,
			Accent:      "#475569",
			Description: "8K DPI optical sensor, quiet clicks, MagSpeed electromagnetic scroll wheel, USB-C fast charging.",
		},
		{
			ID: 8, Name: "Keychron K8 Pro", Category: "peripherals",
			PriceCents: 10900, Stock: 84, Rating: 4.6, Reviews: 1892, Badge: "New",
			Accent:      "#1e293b",
			Description: "TKL hot-swappable mechanical keyboard, QMK/VIA support, wireless Bluetooth 5.1 or wired, RGB backlight.",
		},
		{
			ID: 9, Name: "LG UltraFine 27\" 4K Monitor", Category: "monitors",
			PriceCents: 69900, Stock: 41, Rating: 4.5, Reviews: 731,
			Accent:      "#3b82f6",
			Description: "27-inch 4K IPS, USB-C (96W PD), 98% DCI-P3, height-adjustable stand, anti-glare.",
		},
		{
			ID: 10, Name: "Samsung Odyssey G9 49\"", Category: "monitors",
			PriceCents: 149900, Stock: 15, Rating: 4.7, Reviews: 452, Featured: true, Badge: "Hot",
			Accent:      "#7c3aed",
			Description: "49-inch Dual QHD 240Hz curved gaming display, 1000R curvature, HDR 2000, Quantum Dot color.",
		},
		{
			ID: 11, Name: "Apple Watch Ultra 2", Category: "wearables",
			PriceCents: 79900, Stock: 36, Rating: 4.8, Reviews: 1245, Badge: "New",
			Accent:      "#f59e0b",
			Description: "49mm titanium case, precision dual-frequency GPS, up to 72h battery in low power mode, dive-ready.",
		},
		{
			ID: 12, Name: "Bose QuietComfort 45", Category: "audio",
			PriceCents: 32900, Stock: 58, Rating: 4.6, Reviews: 2108,
			Accent:      "#64748b",
			Description: "World-class noise cancelling, 24-hour battery, plush ear cushions, Bluetooth 5.1, Bose SimpleSync.",
		},
	}
}
