angular.module('sortApp', [])

.controller('mainController', function($scope,$http) {
	$scope.sortType     = 'name'; // set the default sort type
	$scope.sortReverse  = false;  // set the default sort order
	$scope.searchProcess   = '';     // set the default search/filter term

	$scope.processes = []
	
	$http.get('/lrs/api/v1.0/gateway_internal').
        success(function(data) {
            $scope.processes = data;
    });
  
})
.controller('statController', function($scope,$http) {
	$scope.sortType     = 'name'; // set the default sort type
	$scope.sortReverse  = false;  // set the default sort order
	$scope.searchProcess   = '';     // set the default search/filter term

	$scope.stat = []

	$scope.filteredTodos = []
	$scope.currentPage = 1
	$scope.numPerPage = 5
	$scope.maxSize = 5;	



	$http.get('/lrs/api/v1.0/statastic').
	    success(function(data) {
	        $scope.stat = data;           
	});

	$scope.numPages = function () {
	return Math.ceil($scope.stat.length / $scope.numPerPage);
	};

	$scope.$watch('currentPage + numPerPage', function() {
		var begin = (($scope.currentPage - 1) * $scope.numPerPage)
		var end = begin + $scope.numPerPage

		$scope.filteredTodos = $scope.stat.slice(begin, end);

	});	  

  
  
});