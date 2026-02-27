function drawCharts(ports, cities, categories){


    /* Donut dashboard chart */
    var don = (categories && categories.length > 0) ? Morris.Donut({
    labelColor: '#00E1FF',
        element: 'morris-donut-example',
        data: categories,
        colors: ["#ff00cd", "#00E1FF", "#0064d7", "#0a141d", "##15171A","#3eff9e","#f94460",
        "#733fd6", "#863b7a","#b18557",'#33414E', '#1caf9a', '#FEA223',"#1abae0","#63cfad","#7ad840","#db43d0","#fe9130"],
        resize: true,
        parseTime: false
    }) : null;
    /* END Donut dashboard chart */
	
	var horizontal = (ports && ports.length > 0) ? Morris.Bar({
  element: 'morris-horizontal',
  data: ports,
  xkey: 'port',
  ykeys: ['c'],
  labels: ['Total'],
  gridTextSize: '10px',
  gridTextColor: "#0064d7",
        xLabelMargin: 10,
        xLabelAngle: 60,
        hideHover: true,
        resize: true,
  gridLineColor: '#0064d7'
}) : null;
    /* Bar dashboard chart */
    var bar = (cities && cities.length > 0) ? Morris.Bar({
        element: 'morris-bar-example',
        data: cities,
        xkey: 'city',
        ykeys: ['c'],
        labels: ['Total'],
        barColors: ['#00E1FF'],
        gridTextSize: '10px',
          gridTextColor: "#0064d7",
        xLabelMargin: 10,
        xLabelAngle: 60,
        hideHover: true,
        resize: true,
        gridLineColor: '#0064d7'

    }) : null;
    /* END Bar dashboard chart */
    

$('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
  var target = $(e.target).attr("href") // activated tab

  switch (target) {
    case "#tab10":
      if (bar) bar.redraw();
      if (horizontal) horizontal.redraw();
      if (don) don.redraw();
      $(window).trigger('resize');
      break;
  }
});
};

